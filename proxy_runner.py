"""
In-process mitmproxy runner shared by the GUI client and the Windows service.

Wraps building a DumpMaster with the PromptFirewallAddon and running it on an
asyncio loop that can be started/stopped from another thread (the GUI's
Connect/Disconnect buttons, or the service's start/stop).
"""

import asyncio
import logging
import os
import socket
import threading
from typing import Any, Callable, Dict, Optional

log = logging.getLogger("promptfirewall.runner")


def _port_free(host: str, port: int) -> bool:
    """True if (host, port) can be bound right now.

    On Windows a plain bind (no SO_REUSEADDR) fails if another socket already
    owns the port, so this reliably detects a conflicting PromptFirewall
    instance (console / GUI / service) before we waste time loading the model
    and before mitmproxy's listener silently fails with WinError 10048.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _find_free_port(host: str, start: int, tries: int = 20) -> Optional[int]:
    """First free port at or after ``start`` (scans ``tries`` ports)."""
    for port in range(start, start + tries):
        if _port_free(host, port):
            return port
    return None


class ProxyController:
    """Start/stop a mitmproxy instance on its own thread + event loop."""

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        model_path: Optional[str] = None,
        extra_hosts=(),
        paranoid: bool = False,
        confdir: Optional[str] = None,
        on_decision: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
        auto_port: bool = False,
        behavior: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        # When True, hop to the next free port if the requested one is busy.
        # Off by default: the installed proxy's WinINET setting points at a
        # fixed port, so silently moving would send the browser to the wrong
        # place. Handy for dev/demo where nothing is pinned to the port.
        self.auto_port = auto_port
        self.model_path = model_path
        self.extra_hosts = tuple(extra_hosts or ())
        self.paranoid = paranoid
        self.confdir = confdir
        self.on_decision = on_decision
        self.on_status = on_status
        # Behavioural / insider-threat monitor settings (see config.json
        # "behavior" block). None or {"enabled": False} -> DLP-only proxy.
        self.behavior = behavior or {}

        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._master = None
        self._running = threading.Event()
        # Exposed so the GUI can poll the live user-risk baseline/summary.
        self.monitor = None

    # -- status helper ------------------------------------------------------
    def _status(self, msg: str) -> None:
        log.info("status: %s", msg)
        if self.on_status:
            try:
                self.on_status(msg)
            except Exception:
                log.debug("on_status raised", exc_info=True)

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        if self.is_running:
            return
        self._thread = threading.Thread(target=self._run, name="proxy", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        if not self.is_running or self._loop is None:
            return
        self._status("Disconnecting...")
        loop, master = self._loop, self._master
        if master is not None and loop is not None:
            loop.call_soon_threadsafe(master.shutdown)
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._running.clear()
        # Persist the latest baseline so learning survives a disconnect.
        if self.monitor is not None:
            try:
                self.monitor.flush()
            except Exception:
                log.debug("baseline flush on stop failed", exc_info=True)
        self._status("Disconnected")

    # -- behavioural monitor setup -----------------------------------------
    def _setup_behavior(self, proxy_addon) -> None:
        """Build the encrypted baseline store + monitor and inject them into
        the addon module. Any failure degrades to a DLP-only proxy (the
        firewall must keep running even if behaviour analytics can't start)."""
        cfg = self.behavior
        if not cfg or not cfg.get("enabled", True):
            proxy_addon.BEHAVIOR_MONITOR = None
            log.info("Behavioural monitor disabled by config.")
            return
        try:
            from behavior import BaselineStore, BehaviorMonitor
            confdir = self.confdir or os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "PromptFirewallAgent")
            store = BaselineStore(confdir)
            monitor = BehaviorMonitor(
                store,
                learn_min_events=int(cfg.get("learn_min_events", 200)),
                learn_days=int(cfg.get("learn_days", 3)),
                z_threshold=float(cfg.get("z_threshold", 3.0)),
                rarity_threshold=float(cfg.get("rarity_threshold", 0.98)),
                escalate_score=float(cfg.get("escalate_score", 4.0)),
            )
            proxy_addon.BEHAVIOR_MONITOR = monitor
            proxy_addon.BEHAVIOR_THRESHOLDS = cfg.get("thresholds") or None
            proxy_addon.BEHAVIOR_ENFORCE = bool(cfg.get("enforce", True))
            self.monitor = monitor
            log.info("Behavioural monitor active (learning=%s, %d events learned, "
                     "enforce=%s).", monitor.learning, monitor.event_count,
                     proxy_addon.BEHAVIOR_ENFORCE)
        except Exception:
            proxy_addon.BEHAVIOR_MONITOR = None
            self.monitor = None
            log.exception("Behavioural monitor failed to start; DLP-only mode.")

    # -- worker -------------------------------------------------------------
    def _run(self) -> None:
        # Imported here so a missing mitmproxy only fails at connect time, not
        # at GUI import time (lets the UI open and show a clear error).
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        import proxy_addon
        from engine import DetectionEngine

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        # Pre-flight the port BEFORE loading the ~500 MB model, so a conflict
        # fails in milliseconds with a clear message instead of loading the
        # engine and then having mitmproxy silently fail to bind (WinError
        # 10048) while we misleadingly report "Protected".
        host, port = self.listen_host, self.listen_port
        if not _port_free(host, port):
            if self.auto_port:
                alt = _find_free_port(host, port + 1)
                if alt is None:
                    self._status(f"Error: no free port near {port} on {host}.")
                    self._running.clear()
                    self._loop = None
                    return
                log.warning("port %s busy; falling back to %s", port, alt)
                port = self.listen_port = alt
            else:
                self._status(
                    f"Error: port {port} is already in use — another Prompt "
                    f"Firewall instance (console, GUI, or service) is likely "
                    f"running. Stop it, then try again.")
                self._running.clear()
                self._loop = None
                return

        self._status("Loading detection engine...")
        engine = DetectionEngine(model_path=self.model_path)

        # Route addon decisions to the GUI/service callback.
        if self.on_decision:
            proxy_addon.DECISION_SINK = self.on_decision

        # Behavioural / insider-threat monitor (optional). Baseline is stored
        # encrypted under confdir so the SYSTEM service and user GUI share it.
        self._setup_behavior(proxy_addon)

        opts = options.Options(
            listen_host=self.listen_host,
            listen_port=self.listen_port,
        )
        if self.confdir:
            opts.confdir = self.confdir

        async def _amain():
            self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            self._master.addons.add(
                proxy_addon.PromptFirewallAddon(
                    engine=engine, extra_hosts=self.extra_hosts, paranoid=self.paranoid
                )
            )
            self._running.set()
            slm = "SLM active" if engine.llm is not None else "regex-only (SLM absent)"
            self._status(f"Protected — {self.listen_host}:{self.listen_port} ({slm})")
            await self._master.run()

        try:
            loop.run_until_complete(_amain())
        except Exception as exc:
            self._status(f"Error: {exc}")
            log.exception("proxy crashed")
        finally:
            self._running.clear()
            try:
                loop.close()
            except Exception:
                pass
            self._loop = None
            self._master = None