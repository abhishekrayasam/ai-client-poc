"""
mitmproxy addon: the live inspection point.

Two responsibilities:

1. DLP prompt firewall -- for every POST to a known AI host, extract the prompt,
   run the shared DetectionEngine, and BLOCK exfiltration attempts by
   short-circuiting the request with a provider-plausible 403 JSON error.

2. Behavioural / insider-threat monitor -- for EVERY flow, fold the transfer
   (destination, upload/download volume, timing) into a per-user behavioural
   baseline (behavior.BehaviorMonitor) and, when an event is unusual or matches
   an insider-threat indicator (threat_map), escalate it to the SLM
   (engine.evaluate_behavior) for an ALLOW / FLAG / BLOCK decision. Large
   uploads to exfiltration channels are checked at REQUEST time (before the body
   leaves the machine); bulk downloads are checked at RESPONSE time (blocking
   delivery of the payload to the client).

Every decision (DLP or behavioural) is pushed onto a shared sink so the
Citrix-style GUI client can render live activity + a user-risk panel.

Runs three ways:
  * ``mitmdump -s proxy_addon.py``          (standalone dev)
  * imported by ``proxy_runner.run_proxy``  (GUI client / service, in-process)
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, Optional

from mitmproxy import http

import ai_hosts
import threat_map
from engine import DetectionEngine, BLOCK_RESPONSE, BEHAVIOR_BLOCK_RESPONSE

log = logging.getLogger("promptfirewall.proxy")

# A process-wide sink the GUI subscribes to. Kept module-level so the addon
# (created by mitmproxy) and the GUI (created separately) share one channel
# without threading a reference through mitmproxy's addon machinery.
DECISION_SINK = None  # set to a callable(dict) by proxy_runner before start

# Behavioural monitor + settings, injected by proxy_runner before start. When
# BEHAVIOR_MONITOR is None the addon behaves exactly like the original DLP-only
# proxy (backwards compatible / graceful if behaviour is disabled).
BEHAVIOR_MONITOR = None          # behavior.BehaviorMonitor instance
BEHAVIOR_THRESHOLDS = None       # dict overriding threat_map.DEFAULTS
BEHAVIOR_ENFORCE = True          # False -> flag/alert only, never block on behaviour

# Persist the (encrypted) baseline every N recorded events.
_FLUSH_EVERY = 25
# Only bother pre-checking uploads at request time above this size (bytes); tiny
# POSTs (form posts, API pings) can't be meaningful exfil and shouldn't burn SLM.
_UPLOAD_PRECHECK_FLOOR = 1 * 1024 * 1024  # 1 MB


def _publish(decision: Dict[str, Any]) -> None:
    sink = DECISION_SINK
    if sink is not None:
        try:
            sink(decision)
        except Exception:  # a broken UI must never break the proxy
            log.debug("decision sink raised", exc_info=True)


def _block_body(host: str, matched: str) -> bytes:
    """A JSON error the web app will surface cleanly instead of a hang."""
    payload = {
        "error": {
            "type": "prompt_firewall_blocked",
            "code": "content_blocked_by_dlp",
            "message": BLOCK_RESPONSE,
            "matched": matched,
        }
    }
    return json.dumps(payload).encode("utf-8")


def _behavior_block_body(matched: Any) -> bytes:
    payload = {
        "error": {
            "type": "insider_threat_blocked",
            "code": "blocked_by_behavioral_monitor",
            "message": BEHAVIOR_BLOCK_RESPONSE,
            "matched": matched,
        }
    }
    return json.dumps(payload).encode("utf-8")


def _req_bytes(flow: http.HTTPFlow) -> int:
    """Best estimate of request body size without forcing a full read."""
    cl = flow.request.headers.get("content-length")
    if cl and cl.isdigit():
        return int(cl)
    body = flow.request.raw_content or b""
    return len(body)


def _resp_bytes(flow: http.HTTPFlow) -> int:
    if flow.response is None:
        return 0
    cl = flow.response.headers.get("content-length")
    if cl and cl.isdigit():
        return int(cl)
    body = flow.response.raw_content or b""
    return len(body)


class PromptFirewallAddon:
    def __init__(self, engine: Optional[DetectionEngine] = None,
                 extra_hosts=(), paranoid: bool = False) -> None:
        self.engine = engine
        self.extra_hosts = tuple(extra_hosts or ())
        self.paranoid = paranoid
        self._recorded = 0

    # mitmproxy lifecycle hook -- build the engine once the loop is running.
    def running(self) -> None:
        if self.engine is None:
            log.info("Building DetectionEngine inside proxy...")
            self.engine = DetectionEngine()
        log.info("PromptFirewallAddon ready (paranoid=%s, behavior=%s).",
                 self.paranoid, BEHAVIOR_MONITOR is not None)

    # =====================================================================
    # REQUEST: DLP prompt firewall + upload exfil pre-check
    # =====================================================================
    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        prompt_flagged = False

        # ---- DLP prompt firewall (AI POSTs only) ------------------------
        if flow.request.method == "POST" and ai_hosts.is_ai_host(host, self.extra_hosts):
            prompt = ai_hosts.extract_prompt(host, flow.request.raw_content or b"")
            if prompt and prompt.strip():
                start = time.perf_counter()
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(
                    None, self.engine.evaluate, prompt, self.paranoid
                )
                elapsed_ms = (time.perf_counter() - start) * 1000
                prompt_flagged = result.get("action") == "BLOCK"

                decision = {
                    "host": host,
                    "action": result.get("action"),
                    "phase": result.get("phase"),
                    "matched": result.get("matched") or result.get("regex_hits"),
                    "latency_ms": round(elapsed_ms, 1),
                    "excerpt": prompt.strip()[:120],
                    "type": "dlp",
                }
                _publish(decision)

                if result.get("action") == "BLOCK":
                    log.warning("BLOCK %s [%s] %s", host, decision["phase"],
                                decision["matched"])
                    flow.response = http.Response.make(
                        403,
                        _block_body(host, str(decision["matched"])),
                        {"Content-Type": "application/json"},
                    )
                    # Still record the (attempted) event for the baseline below,
                    # tagged as a flagged prompt, then return.
                    self._record_flow(flow, host, has_prompt=True,
                                      prompt_flagged=True)
                    return
                else:
                    log.info("ALLOW %s [%s] %.1fms", host, decision["phase"],
                             elapsed_ms)

        # ---- Behavioural upload pre-check (all flows) -------------------
        mon = BEHAVIOR_MONITOR
        if mon is None:
            return

        req = _req_bytes(flow)
        if req < _UPLOAD_PRECHECK_FLOOR:
            return  # too small to be exfil; the response hook still records it

        event = self._build_event(flow, host, req_bytes=req, resp_bytes=0,
                                   has_prompt=prompt_flagged or None,
                                   prompt_flagged=prompt_flagged)
        # Only spend an SLM call when this actually trips an indicator.
        snapshot = mon.snapshot()
        hits = threat_map.match_indicators(event, snapshot, BEHAVIOR_THRESHOLDS)
        if not hits:
            return

        verdict = await self._adjudicate(event, hits, mon)
        # This is an upload we can still stop: record it, then block the request.
        self._record_flow(flow, host, req_bytes=req, resp_bytes=0,
                          has_prompt=prompt_flagged or None,
                          prompt_flagged=prompt_flagged)
        if BEHAVIOR_ENFORCE and verdict.get("action") == "BLOCK":
            log.warning("BEHAVIOR BLOCK (upload) %s %s", host, verdict.get("matched"))
            flow.response = http.Response.make(
                403,
                _behavior_block_body(verdict.get("matched")),
                {"Content-Type": "application/json"},
            )

    # =====================================================================
    # RESPONSE: baseline recording + bulk-download / general assessment
    # =====================================================================
    async def response(self, flow: http.HTTPFlow) -> None:
        mon = BEHAVIOR_MONITOR
        if mon is None:
            return
        # A flow blocked at request time already recorded itself.
        if flow.metadata.get("pf_recorded"):
            return

        host = flow.request.pretty_host
        req = _req_bytes(flow)
        resp = _resp_bytes(flow)
        event = self._build_event(flow, host, req_bytes=req, resp_bytes=resp)

        # Assess against the (pre-record) snapshot so the current event is judged
        # relative to prior behaviour, not itself.
        snapshot = mon.snapshot()
        anomaly = mon.assess(event)
        hits = threat_map.match_indicators(event, snapshot, BEHAVIOR_THRESHOLDS)

        # Fold into the baseline / rolling counters.
        self._record_flow(flow, host, req_bytes=req, resp_bytes=resp)

        # Nothing unusual -> nothing to adjudicate or surface.
        if not hits and anomaly.get("level", "low") == "low":
            return

        event["reasons"] = anomaly.get("reasons", [])
        verdict = await self._adjudicate(event, hits, mon,
                                         anomaly=anomaly)
        if BEHAVIOR_ENFORCE and verdict.get("action") == "BLOCK":
            log.warning("BEHAVIOR BLOCK (download) %s %s", host,
                        verdict.get("matched"))
            flow.response = http.Response.make(
                403,
                _behavior_block_body(verdict.get("matched")),
                {"Content-Type": "application/json"},
            )

    # =====================================================================
    # Helpers
    # =====================================================================
    def _build_event(self, flow: http.HTTPFlow, host: str,
                     req_bytes: int = 0, resp_bytes: int = 0,
                     has_prompt: Optional[bool] = None,
                     prompt_flagged: bool = False) -> Dict[str, Any]:
        category = threat_map.classify_destination(host)
        mon = BEHAVIOR_MONITOR
        # "new" only counts once the baseline is established, so learning-phase
        # first-contacts don't cry wolf.
        new_host = False
        if mon is not None and not mon.learning:
            new_host = bool(host) and host not in mon.snapshot().get("known_hosts", set())
        event = {
            "host": host,
            "category": category,
            "hour": time.localtime().tm_hour,
            "req_bytes": req_bytes,
            "resp_bytes": resp_bytes,
            "new_host": new_host,
            "source": "proxy",
        }
        if has_prompt:
            event["has_prompt"] = True
            event["prompt_flagged"] = prompt_flagged
        return event

    def _record_flow(self, flow: http.HTTPFlow, host: str,
                     req_bytes: Optional[int] = None,
                     resp_bytes: Optional[int] = None,
                     has_prompt: Optional[bool] = None,
                     prompt_flagged: bool = False) -> None:
        mon = BEHAVIOR_MONITOR
        if mon is None:
            return
        if flow.metadata.get("pf_recorded"):
            return
        if req_bytes is None:
            req_bytes = _req_bytes(flow)
        if resp_bytes is None:
            resp_bytes = _resp_bytes(flow)
        try:
            mon.record({
                "host": host,
                "category": threat_map.classify_destination(host),
                "hour": time.localtime().tm_hour,
                "req_bytes": req_bytes,
                "resp_bytes": resp_bytes,
            })
            flow.metadata["pf_recorded"] = True
            self._recorded += 1
            if self._recorded % _FLUSH_EVERY == 0:
                mon.flush()
        except Exception:
            log.debug("behaviour record failed", exc_info=True)

    async def _adjudicate(self, event: Dict[str, Any], hits, mon,
                          anomaly: Optional[Dict[str, Any]] = None
                          ) -> Dict[str, Any]:
        """Escalate an unusual event to the SLM and publish the decision."""
        context = {
            "event": event,
            "baseline": mon.baseline_summary(),
            "reasons": event.get("reasons", []),
            "indicators": hits,
        }
        if anomaly is not None:
            context["score"] = anomaly.get("score")
            context["level"] = anomaly.get("level")

        loop = asyncio.get_running_loop()
        try:
            verdict = await loop.run_in_executor(
                None, self.engine.evaluate_behavior, context, self.paranoid
            )
        except Exception:
            log.exception("evaluate_behavior failed; failing to FLAG")
            verdict = {"action": "FLAG", "phase": "BEHAVIOR_ERROR",
                       "matched": [h.get("id") for h in hits],
                       "severity": threat_map.max_severity(hits)}

        decision = {
            "host": event.get("host", ""),
            "action": verdict.get("action"),
            "phase": verdict.get("phase"),
            "matched": verdict.get("matched") or [h.get("id") for h in hits],
            "severity": verdict.get("severity") or threat_map.max_severity(hits),
            "reasons": event.get("reasons", []),
            "indicators": [h.get("id") for h in hits],
            "excerpt": "; ".join(h.get("detail", "") for h in hits)[:120],
            "type": "behavior",
            "learning": mon.learning,
        }
        _publish(decision)
        return verdict


# When loaded via `mitmdump -s proxy_addon.py`, mitmproxy looks for `addons`.
addons = [PromptFirewallAddon()]
