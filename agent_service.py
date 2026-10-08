"""
Windows service wrapper (headless) for the Prompt Firewall DLP proxy.

The Citrix-style GUI (gui_client.py) is the interactive front end; this service
is the optional always-on background variant that runs the same proxy without a
window. Both share proxy_runner.ProxyController.

Also provides ``--gen-ca`` so the MSI can pre-generate the mitmproxy root CA at
install time and trust it via certutil.

Usage (as admin):
    python agent_service.py install
    python agent_service.py start
    python agent_service.py stop
    python agent_service.py remove
    python agent_service.py --console     # run in foreground for debugging
    python agent_service.py --gen-ca DIR  # generate CA into DIR, then exit
"""

import logging
import os
import sys
import threading
import time

CONFDIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                       "PromptFirewallAgent")
LOGDIR = os.path.join(CONFDIR, "logs")


def _configure_logging() -> None:
    os.makedirs(LOGDIR, exist_ok=True)
    from logging.handlers import RotatingFileHandler
    handler = RotatingFileHandler(os.path.join(LOGDIR, "agent.log"),
                                  maxBytes=2_000_000, backupCount=5)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)


def _app_dir() -> str:
    """Directory to resolve config/model against.

    When frozen, the SCM launches us with CWD=System32 and ``__file__`` points
    into the PyInstaller temp dir, so neither is a reliable base. The install
    dir (next to the exe) is. In dev, fall back to this file's directory.
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _load_config() -> dict:
    import json
    here = _app_dir()
    path = os.path.join(here, "config.json")
    cfg = {
        "listen_host": "127.0.0.1",
        "listen_port": 8080,
        "model_path": None,
        "ai_hosts": [],
        "paranoid": False,
        "confdir": CONFDIR,
        "auto_port": False,
        "behavior": {},
    }
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    except Exception:
        pass
    # A null/empty confdir in config.json must fall back to the ProgramData dir
    # (setdefault won't replace an explicit null). This keeps the proxy's CA in
    # ONE place — the dir the installer generated + trusted — instead of
    # mitmproxy's default %USERPROFILE%\.mitmproxy, which nothing trusts.
    if not cfg.get("confdir"):
        cfg["confdir"] = CONFDIR
    # Resolve a relative model_path against the install dir (not System32).
    mp = cfg.get("model_path")
    if mp and not os.path.isabs(mp):
        cfg["model_path"] = os.path.join(here, mp)
    return cfg


def _decision_logger(d: dict) -> None:
    logging.getLogger("promptfirewall.decision").info(
        "%s %s [%s] %s", d.get("action"), d.get("host"), d.get("phase"),
        d.get("matched"))


def gen_ca(confdir: str) -> int:
    """Force mitmproxy to generate its CA into ``confdir`` and exit.

    mitmproxy writes mitmproxy-ca-cert.cer (the file certutil trusts) the first
    time a CertStore is created for a confdir.
    """
    os.makedirs(confdir, exist_ok=True)
    from mitmproxy.certs import CertStore
    CertStore.from_store(confdir, "mitmproxy", 2048)
    cer = os.path.join(confdir, "mitmproxy-ca-cert.cer")
    print(cer if os.path.isfile(cer) else "CA generation failed", flush=True)
    return 0 if os.path.isfile(cer) else 1


def run_console() -> int:
    _configure_logging()
    from proxy_runner import ProxyController
    cfg = _load_config()
    ctl = ProxyController(
        listen_host=cfg["listen_host"], listen_port=int(cfg["listen_port"]),
        model_path=cfg.get("model_path"), extra_hosts=cfg.get("ai_hosts") or (),
        paranoid=bool(cfg.get("paranoid")), confdir=cfg.get("confdir"),
        auto_port=bool(cfg.get("auto_port")), behavior=cfg.get("behavior") or {},
        on_decision=_decision_logger,
        on_status=lambda s: logging.getLogger("promptfirewall").info("status: %s", s),
    )
    ctl.start()
    print("Prompt Firewall running (console mode). Ctrl+C to stop.")
    try:
        while ctl.is_running or True:
            time.sleep(1)
    except KeyboardInterrupt:
        ctl.stop()
    return 0


# -- Windows service class (only imported when pywin32 is present) -------------
def _build_service_class():
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager  # noqa: F401
    from proxy_runner import ProxyController

    class PromptFirewallService(win32serviceutil.ServiceFramework):
        _svc_name_ = "PromptFirewallAgent"
        _svc_display_name_ = "Prompt Firewall Secure Access Agent"
        _svc_description_ = ("On-device AI prompt firewall / DLP proxy. Inspects "
                             "AI prompt traffic and blocks PII exfiltration.")

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_evt = win32event.CreateEvent(None, 0, 0, None)
            self._ctl = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self._ctl is not None:
                try:
                    self._ctl.stop()
                except Exception:
                    logging.getLogger("promptfirewall").exception("stop failed")
            win32event.SetEvent(self._stop_evt)

        def SvcDoRun(self):
            # Report RUNNING *first* so the SCM never times out (error 1053).
            # All heavy work (engine + ~500 MB model load, proxy start) then
            # happens on a worker thread; a startup failure logs a traceback
            # and signals stop instead of hanging or crashing silently.
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            try:
                _configure_logging()
            except Exception:
                pass
            logging.getLogger("promptfirewall").info(
                "Service reported RUNNING; initializing proxy in background.")
            threading.Thread(target=self._serve, name="pf-serve",
                             daemon=True).start()
            win32event.WaitForSingleObject(self._stop_evt, win32event.INFINITE)

        def _serve(self):
            log = logging.getLogger("promptfirewall")
            try:
                cfg = _load_config()
                self._ctl = ProxyController(
                    listen_host=cfg["listen_host"],
                    listen_port=int(cfg["listen_port"]),
                    model_path=cfg.get("model_path"),
                    extra_hosts=cfg.get("ai_hosts") or (),
                    paranoid=bool(cfg.get("paranoid")),
                    confdir=cfg.get("confdir"),
                    auto_port=bool(cfg.get("auto_port")),
                    behavior=cfg.get("behavior") or {},
                    on_decision=_decision_logger,
                )
                self._ctl.start()
                log.info("Proxy started on %s:%s", cfg["listen_host"],
                         cfg["listen_port"])
            except Exception:
                log.exception("Proxy init failed; stopping service.")
                win32event.SetEvent(self._stop_evt)

    return PromptFirewallService


def main() -> int:
    if "--gen-ca" in sys.argv:
        idx = sys.argv.index("--gen-ca")
        confdir = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else CONFDIR
        return gen_ca(confdir)

    if "--console" in sys.argv:
        return run_console()

    try:
        import win32serviceutil
        import servicemanager
    except ImportError:
        print("pywin32 not installed. Use --console to run in the foreground, "
              "or install pywin32 for Windows service mode.")
        return 1

    svc = _build_service_class()

    # When the SCM launches the (frozen) exe it passes no CLI verb -- in that
    # case we must hand control to the service dispatcher, not HandleCommandLine.
    # HandleCommandLine covers the install/start/stop/remove verbs used by
    # configure.ps1 at install/uninstall time.
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(svc)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(svc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())