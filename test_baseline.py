"""
Interactive tester for the behavioural / insider-threat baseline.

Runs the SAME pipeline the live proxy uses -- BehaviorMonitor (learn + score),
threat_map (indicator matching), and DetectionEngine.evaluate_behavior (the SLM
adjudication) -- but drives it with scripted events so you can see it work in
seconds instead of over days of real browsing.

It uses a throwaway temp folder for the encrypted baseline, so it does NOT touch
the real agent's data in %ProgramData%.

Run:
    python test_baseline.py
"""

import logging
import tempfile

logging.basicConfig(level=logging.WARNING,
                    format="%(levelname)s %(name)s: %(message)s")

from behavior import BaselineStore, BehaviorMonitor
from engine import DetectionEngine
import threat_map

MB = 1024 * 1024


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="pf-baseline-test-")
    print(f"Using throwaway baseline folder: {tmp}\n")

    # Fake clock so we control the "learning window" without waiting.
    clk = {"t": 1_700_000_000.0}
    store = BaselineStore(tmp, clock=lambda: clk["t"])
    # Short window so learning finishes after ~60 events (instead of 200 / 3 days).
    mon = BehaviorMonitor(store, learn_min_events=50, learn_days=0,
                          clock=lambda: clk["t"])

    # --- 1. Teach it a normal routine -----------------------------------
    print("1) Learning a normal routine (small browsing to a few work sites)...")
    for i in range(60):
        clk["t"] += 60
        mon.record({
            "host": ["github.com", "docs.python.org", "mail.google.com"][i % 3],
            "category": "generic",
            "hour": 10 + (i % 4),          # active 10:00-13:00
            "req_bytes": 2_000 + (i % 5) * 100,
            "resp_bytes": 50_000 + (i % 7) * 1_000,
        })
    store.save()
    print(f"   baseline learning finished: {not mon.learning} "
          f"({mon.event_count} events observed)\n")

    # --- 2. Load the detection engine (uses the SLM if the model is present)
    print("2) Loading the detection engine (this loads the AI model)...")
    engine = DetectionEngine()
    print(f"   AI model (SLM) loaded: {engine.llm is not None}\n")

    # --- 3. Feed it events and print the verdicts -----------------------
    scenarios = [
        ("Normal: small download from a known work site",
         {"host": "github.com", "category": "code_host", "hour": 11,
          "req_bytes": 1_500, "resp_bytes": 45_000}),
        ("Bulk download: 4 GB pulled from an internal app",
         {"host": "intranet.corp", "category": "generic", "hour": 11,
          "req_bytes": 800, "resp_bytes": 4_000 * MB}),
        ("Large upload to personal cloud (mega.nz), 2am",
         {"host": "mega.nz", "category": "cloud_storage", "hour": 2,
          "req_bytes": 210 * MB, "resp_bytes": 0}),
        ("First use of an anonymous paste/share site",
         {"host": "transfer.sh", "category": "paste_share", "hour": 13,
          "req_bytes": 8 * MB, "resp_bytes": 0}),
    ]

    print("3) Verdicts:\n" + "=" * 72)
    for title, ev in scenarios:
        # Mark hosts the baseline has never seen (as the proxy does post-learning).
        snap = mon.snapshot()
        ev["new_host"] = bool(ev["host"]) and ev["host"] not in snap["known_hosts"]

        anomaly = mon.assess(ev)
        hits = threat_map.match_indicators(ev, snap)
        context = {
            "event": ev,
            "baseline": mon.baseline_summary(),
            "reasons": anomaly["reasons"],
            "indicators": hits,
            "score": anomaly["score"],
            "level": anomaly["level"],
        }
        verdict = engine.evaluate_behavior(context)

        print(f"\n{title}")
        print(f"   -> ACTION : {verdict['action']}   (via {verdict['phase']})")
        print(f"      risk   : score={anomaly['score']} level={anomaly['level']}")
        if hits:
            print(f"      matched: {[h['id'] for h in hits]}")
        if anomaly["reasons"]:
            print(f"      reasons: {anomaly['reasons']}")

    print("\n" + "=" * 72)
    print("Expected: the normal event ALLOWs; the exfil-style events FLAG or "
          "BLOCK.\n(Large uploads to cloud/paste sites are BLOCKed even without "
          "the AI model, because\nthey match a 'critical' insider-threat "
          "indicator.)")


if __name__ == "__main__":
    main()
