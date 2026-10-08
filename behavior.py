"""
Behavioural baseline + anomaly monitor for the Prompt Firewall agent.

This module learns a per-user behavioural baseline from the traffic the proxy
already sees (destinations, upload/download volume, timing, rarity) and scores
each new event for how far it deviates. The baseline is persisted to an
ENCRYPTED file on the client machine so it can survive restarts without leaking
a user's activity profile in cleartext.

Design notes
------------
* Signal source is the proxy's own flows. Real endpoint telemetry (USB, local
  file copies, genuinely offline activity) would need a kernel/ETW sensor and is
  out of scope for this POC -- but ``BehaviorMonitor.record`` is a clean ingest
  point such a sensor could feed later.
* Statistics are cheap and online (Welford for continuous features, frequency
  tables for categorical ones), so ``record``/``assess`` run on every flow
  without touching the SLM. Only *unusual* events get escalated to the LLM
  (see engine.evaluate_behavior), keeping cost bounded.
* Encryption: Windows DPAPI (machine-scoped) when pywin32 is present -- no key
  to manage, bound to the machine so both the SYSTEM service and the user's GUI
  can read it. A stdlib authenticated-stream fallback (scrypt-derived key +
  HMAC-SHA256 keystream, encrypt-then-MAC) is used only where DPAPI is absent
  (e.g. dev boxes); it is obfuscation-grade and clearly logged as such.
"""

import hashlib
import hmac
import json
import logging
import math
import os
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("promptfirewall.behavior")

BASELINE_VERSION = 1
_MAGIC = b"PFB1"  # stdlib-fallback container tag


# =============================================================================
# Encryption backends
# =============================================================================
class SecretBox:
    """Encrypt/decrypt bytes at rest. Chooses the best available backend."""

    def __init__(self, backend: str, confdir: str) -> None:
        self.backend = backend
        self.confdir = confdir
        self._master: Optional[bytes] = None  # stdlib fallback only

    @classmethod
    def choose(cls, confdir: str) -> "SecretBox":
        os.makedirs(confdir, exist_ok=True)
        try:
            import win32crypt  # noqa: F401
            log.info("Baseline encryption: Windows DPAPI (machine-scoped).")
            return cls("dpapi", confdir)
        except Exception:
            log.warning(
                "pywin32/DPAPI unavailable; using stdlib authenticated-stream "
                "fallback for the baseline (obfuscation-grade, dev only).")
            return cls("stdlib", confdir)

    # -- DPAPI ------------------------------------------------------------
    def _dpapi_encrypt(self, data: bytes) -> bytes:
        import win32crypt
        # CRYPTPROTECT_LOCAL_MACHINE (0x4) -> any account on this box can
        # decrypt, so the SYSTEM service and the user GUI share one baseline.
        return win32crypt.CryptProtectData(
            data, "PromptFirewallBaseline", None, None, None, 0x4)

    def _dpapi_decrypt(self, blob: bytes) -> bytes:
        import win32crypt
        _desc, out = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
        return out

    # -- stdlib fallback --------------------------------------------------
    def _master_key(self) -> bytes:
        if self._master is not None:
            return self._master
        salt_path = os.path.join(self.confdir, "baseline.salt")
        try:
            with open(salt_path, "rb") as f:
                salt = f.read()
            if len(salt) < 16:
                raise ValueError("short salt")
        except Exception:
            salt = os.urandom(16)
            tmp = salt_path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(salt)
            os.replace(tmp, salt_path)
        # Machine-bound passphrase (NIC id). Not a real secret -- this backend
        # is dev-only; production uses DPAPI.
        passphrase = f"promptfirewall:{uuid.getnode()}".encode("utf-8")
        self._master = hashlib.scrypt(passphrase, salt=salt, n=2 ** 14, r=8,
                                      p=1, dklen=32)
        return self._master

    @staticmethod
    def _hkdf(key: bytes, info: bytes, n: int = 32) -> bytes:
        out, t, i = b"", b"", 1
        while len(out) < n:
            t = hmac.new(key, t + info + bytes([i]), hashlib.sha256).digest()
            out += t
            i += 1
        return out[:n]

    @classmethod
    def _keystream(cls, key: bytes, nonce: bytes, n: int) -> bytes:
        out, ctr = b"", 0
        while len(out) < n:
            out += hmac.new(key, nonce + ctr.to_bytes(8, "big"),
                            hashlib.sha256).digest()
            ctr += 1
        return out[:n]

    def _stdlib_encrypt(self, data: bytes) -> bytes:
        master = self._master_key()
        enc_key = self._hkdf(master, b"pf-enc")
        mac_key = self._hkdf(master, b"pf-mac")
        nonce = os.urandom(16)
        ks = self._keystream(enc_key, nonce, len(data))
        ct = bytes(a ^ b for a, b in zip(data, ks))
        tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
        return _MAGIC + nonce + tag + ct

    def _stdlib_decrypt(self, blob: bytes) -> bytes:
        if blob[:4] != _MAGIC:
            raise ValueError("bad container magic")
        nonce, tag, ct = blob[4:20], blob[20:52], blob[52:]
        master = self._master_key()
        enc_key = self._hkdf(master, b"pf-enc")
        mac_key = self._hkdf(master, b"pf-mac")
        expect = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expect):
            raise ValueError("authentication failed (tampered or wrong key)")
        ks = self._keystream(enc_key, nonce, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks))

    # -- public -----------------------------------------------------------
    def encrypt(self, data: bytes) -> bytes:
        return self._dpapi_encrypt(data) if self.backend == "dpapi" \
            else self._stdlib_encrypt(data)

    def decrypt(self, blob: bytes) -> bytes:
        return self._dpapi_decrypt(blob) if self.backend == "dpapi" \
            else self._stdlib_decrypt(blob)


# =============================================================================
# Online statistics
# =============================================================================
class _Running:
    """Welford online mean/variance."""

    __slots__ = ("n", "mean", "m2")

    def __init__(self, n: int = 0, mean: float = 0.0, m2: float = 0.0) -> None:
        self.n, self.mean, self.m2 = n, mean, m2

    def add(self, x: float) -> None:
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0

    def z(self, x: float) -> float:
        s = self.std
        return (x - self.mean) / s if s > 0 else 0.0

    def to_dict(self) -> Dict[str, float]:
        return {"n": self.n, "mean": self.mean, "m2": self.m2}

    @classmethod
    def from_dict(cls, d: Dict[str, float]) -> "_Running":
        return cls(int(d.get("n", 0)), float(d.get("mean", 0.0)),
                   float(d.get("m2", 0.0)))


# =============================================================================
# Baseline monitor
# =============================================================================
# Continuous features tracked with Welford stats (log1p of byte counts so the
# distribution isn't dominated by the occasional huge transfer).
_CONTINUOUS = ("req_bytes_log", "resp_bytes_log", "daily_download_log",
               "daily_upload_log")
# Categorical features tracked as frequency tables.
_CATEGORICAL = ("host", "category", "hour")


class BehaviorMonitor:
    """Learns a baseline from events and scores new ones for deviation.

    ``record(event)`` folds an event into the baseline (during the learning
    window) and updates rolling per-day counters. ``assess(event)`` returns a
    deviation score + human-readable reasons without mutating state.
    """

    def __init__(
        self,
        store: "BaselineStore",
        learn_min_events: int = 200,
        learn_days: int = 3,
        z_threshold: float = 3.0,
        rarity_threshold: float = 0.98,
        escalate_score: float = 4.0,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.store = store
        self.learn_min_events = learn_min_events
        self.learn_days = learn_days
        self.z_threshold = z_threshold
        self.rarity_threshold = rarity_threshold
        self.escalate_score = escalate_score
        self._clock = clock or time.time
        self.b = store.data  # the live baseline dict (see BaselineStore)
        # In-memory rolling counters for the current calendar day.
        self._day = self._today()
        self._day_download = 0
        self._day_upload = 0
        # record() runs on the proxy thread while the GUI thread polls
        # snapshot()/baseline_summary(); without this, iterating the categorical
        # dicts during a concurrent mutation raises "dictionary changed size
        # during iteration". Reentrant so assess()->rarity() can re-acquire.
        self._lock = threading.RLock()

    # -- helpers ----------------------------------------------------------
    def _today(self) -> str:
        return time.strftime("%Y-%m-%d", time.localtime(self._clock()))

    def _running(self, name: str) -> _Running:
        return _Running.from_dict(self.b["continuous"].setdefault(
            name, {"n": 0, "mean": 0.0, "m2": 0.0}))

    def _save_running(self, name: str, r: _Running) -> None:
        self.b["continuous"][name] = r.to_dict()

    def _cat_table(self, name: str) -> Dict[str, int]:
        return self.b["categorical"].setdefault(name, {})

    # -- learning-phase state --------------------------------------------
    @property
    def event_count(self) -> int:
        return int(self.b.get("event_count", 0))

    @property
    def learning(self) -> bool:
        """True while the baseline is still being established."""
        if self.event_count < self.learn_min_events:
            return True
        age_days = (self._clock() - self.b.get("created", self._clock())) / 86400.0
        return age_days < self.learn_days

    def baseline_summary(self) -> Dict[str, Any]:
        """Compact, LLM-friendly description of normal behaviour."""
        with self._lock:
            return self._baseline_summary_locked()

    def _baseline_summary_locked(self) -> Dict[str, Any]:
        def top(name: str, k: int = 5) -> List[str]:
            tab = self.b["categorical"].get(name, {})
            return [key for key, _ in sorted(tab.items(), key=lambda kv: -kv[1])[:k]]
        dl = self._running("daily_download_log")
        ul = self._running("daily_upload_log")
        return {
            "events_learned": self.event_count,
            "learning": self.learning,
            "status": "learning" if self.learning else "active",
            "typical_hosts": top("host"),
            "typical_categories": top("category"),
            "active_hours": sorted(
                int(h) for h in self.b["categorical"].get("hour", {})),
            "typical_daily_download_mb": round(
                (math.expm1(dl.mean)) / 1_000_000, 2) if dl.n else 0.0,
            "typical_daily_upload_mb": round(
                (math.expm1(ul.mean)) / 1_000_000, 2) if ul.n else 0.0,
            "session_download_mb": round(self._day_download / 1_000_000, 2),
            "session_upload_mb": round(self._day_upload / 1_000_000, 2),
        }

    def snapshot(self) -> Dict[str, Any]:
        """State the threat-map matcher needs (baseline + current day)."""
        with self._lock:
            dl = self._running("daily_download_log")
            ul = self._running("daily_upload_log")
            return {
                "learning": self.learning,
                "session_download_bytes": self._day_download,
                "session_upload_bytes": self._day_upload,
                "typical_daily_download_bytes": math.expm1(dl.mean) if dl.n else 0.0,
                "typical_daily_upload_bytes": math.expm1(ul.mean) if ul.n else 0.0,
                "active_hours": set(self.b["categorical"].get("hour", {})),
                "known_hosts": set(self.b["categorical"].get("host", {})),
            }

    # -- day rollover -----------------------------------------------------
    def _maybe_rollover(self) -> None:
        today = self._today()
        if today == self._day:
            return
        # Fold the finished day's totals into the baseline (learning only).
        if self.learning:
            for name, total in (("daily_download_log", self._day_download),
                                ("daily_upload_log", self._day_upload)):
                r = self._running(name)
                r.add(math.log1p(total))
                self._save_running(name, r)
        self._day = today
        self._day_download = 0
        self._day_upload = 0

    # -- ingest -----------------------------------------------------------
    def record(self, event: Dict[str, Any]) -> None:
        """Fold an event into rolling counters and (while learning) the baseline."""
        with self._lock:
            self._maybe_rollover()
            req = int(event.get("req_bytes", 0) or 0)
            resp = int(event.get("resp_bytes", 0) or 0)
            self._day_upload += req
            self._day_download += resp

            self.b["event_count"] = self.event_count + 1
            self.b["updated"] = self._clock()

            if self.learning:
                for name, val in (("req_bytes_log", math.log1p(req)),
                                  ("resp_bytes_log", math.log1p(resp))):
                    r = self._running(name)
                    r.add(val)
                    self._save_running(name, r)
                for name in _CATEGORICAL:
                    key = str(event.get(name, ""))
                    if key:
                        tab = self._cat_table(name)
                        tab[key] = tab.get(key, 0) + 1

    def rarity(self, name: str, key: str) -> float:
        """0 = common, 1 = never observed for this user."""
        tab = self.b["categorical"].get(name, {})
        total = sum(tab.values())
        if total == 0:
            return 0.0  # nothing learned yet -> don't cry wolf
        return 1.0 - (tab.get(str(key), 0) / total)

    # -- scoring ----------------------------------------------------------
    def assess(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Return {score, level, reasons, learning} for an event (no mutation)."""
        with self._lock:
            reasons: List[str] = []
            score = 0.0

            for name, raw in (("req_bytes_log", event.get("req_bytes", 0)),
                              ("resp_bytes_log", event.get("resp_bytes", 0))):
                r = self._running(name)
                if r.n < 10:
                    continue  # too little history to judge
                z = r.z(math.log1p(int(raw or 0)))
                if z >= self.z_threshold:
                    score += min(z, 10.0)
                    kind = "upload" if name.startswith("req") else "download"
                    reasons.append(f"{kind} volume {z:.1f} std-devs above your baseline")

            for name in _CATEGORICAL:
                key = str(event.get(name, ""))
                if not key:
                    continue
                r = self.rarity(name, key)
                if r >= self.rarity_threshold:
                    score += 2.0
                    label = {"host": "destination", "category": "destination type",
                             "hour": "time-of-day"}[name]
                    reasons.append(f"unusual {label} for you: {key}")

            # Session cumulative download vs typical day.
            dl = self._running("daily_download_log")
            if dl.n >= 2:
                typical = math.expm1(dl.mean)
                if typical > 0 and self._day_download > 3 * typical:
                    score += 3.0
                    reasons.append(
                        f"today's download volume "
                        f"({self._day_download/1e6:.0f}MB) far exceeds your typical "
                        f"{typical/1e6:.0f}MB/day")

            level = ("critical" if score >= 8 else "high" if score >= 5
                     else "medium" if score >= self.escalate_score else "low")
            return {"score": round(score, 2), "level": level, "reasons": reasons,
                    "learning": self.learning}

    def flush(self) -> None:
        with self._lock:
            self.store.save()


# =============================================================================
# Encrypted persistence
# =============================================================================
def _empty_baseline(now: float) -> Dict[str, Any]:
    return {
        "version": BASELINE_VERSION,
        "created": now,
        "updated": now,
        "event_count": 0,
        "continuous": {},
        "categorical": {},
    }


class BaselineStore:
    """Loads/saves the baseline dict as an encrypted file under ``confdir``."""

    def __init__(self, confdir: str, filename: str = "baseline.enc",
                 clock: Optional[Callable[[], float]] = None) -> None:
        self.confdir = confdir
        self.path = os.path.join(confdir, filename)
        self._clock = clock or time.time
        self.box = SecretBox.choose(confdir)
        self.data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        if not os.path.isfile(self.path):
            return _empty_baseline(self._clock())
        try:
            with open(self.path, "rb") as f:
                blob = f.read()
            data = json.loads(self.box.decrypt(blob).decode("utf-8"))
            if data.get("version") != BASELINE_VERSION:
                log.warning("Baseline version mismatch; starting fresh.")
                return _empty_baseline(self._clock())
            data.setdefault("continuous", {})
            data.setdefault("categorical", {})
            return data
        except Exception as exc:
            log.warning("Could not read baseline (%s); starting fresh.", exc)
            return _empty_baseline(self._clock())

    def save(self) -> None:
        try:
            blob = self.box.encrypt(
                json.dumps(self.data, separators=(",", ":")).encode("utf-8"))
            tmp = self.path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(blob)
            os.replace(tmp, self.path)
        except Exception as exc:
            log.error("Failed to persist baseline: %s", exc)


# =============================================================================
# Self-test:  python behavior.py --selftest
# =============================================================================
def _selftest() -> int:
    import tempfile
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    tmp = tempfile.mkdtemp(prefix="pf-behavior-")
    print(f"\nBehaviour self-test (confdir={tmp})\n")

    # 1) Encryption round-trips and detects tampering.
    box = SecretBox.choose(tmp)
    sample = b'{"hello":"world","n":123}'
    blob = box.encrypt(sample)
    assert box.decrypt(blob) == sample, "round-trip failed"
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    tamper_caught = False
    try:
        box.decrypt(bytes(tampered))
    except Exception:
        tamper_caught = True
    # DPAPI also rejects tampering; stdlib backend definitely does.
    print(f"[{'PASS' if tamper_caught else 'WARN'}] encryption round-trip + "
          f"tamper detection (backend={box.backend})")

    # 2) Learn a routine, then flag outliers.
    clk = {"t": 1_700_000_000.0}
    store = BaselineStore(tmp, clock=lambda: clk["t"])
    mon = BehaviorMonitor(store, learn_min_events=50, learn_days=0,
                          clock=lambda: clk["t"])

    # Routine: small browsing to a few known hosts during work hours.
    for i in range(60):
        clk["t"] += 60
        mon.record({
            "host": ["github.com", "docs.python.org", "mail.google.com"][i % 3],
            "category": "generic", "hour": 10 + (i % 4),
            "req_bytes": 1_500 + (i % 5) * 100,
            "resp_bytes": 40_000 + (i % 7) * 1_000,
        })
    store.save()
    assert not mon.learning, "should have finished learning after 50+ events"

    # Outlier: huge download from a never-seen host at an odd hour.
    outlier = {"host": "mega.nz", "category": "cloud_storage", "hour": 3,
               "req_bytes": 2_000, "resp_bytes": 5_000_000_000}
    a = mon.assess(outlier)
    normal = {"host": "github.com", "category": "generic", "hour": 11,
              "req_bytes": 1_600, "resp_bytes": 42_000}
    b = mon.assess(normal)
    print(f"[{'PASS' if a['score'] > b['score'] else 'FAIL'}] outlier scored "
          f"higher ({a['score']} vs {b['score']})")
    print(f"[{'PASS' if a['level'] in ('high', 'critical') else 'FAIL'}] outlier "
          f"level={a['level']}  reasons={a['reasons']}")
    print(f"[{'PASS' if b['level'] == 'low' else 'FAIL'}] normal event level={b['level']}")

    # 3) Baseline persists across reloads (decrypts fine).
    store2 = BaselineStore(tmp, clock=lambda: clk["t"])
    reloaded = int(store2.data.get("event_count", 0))
    print(f"[{'PASS' if reloaded >= 60 else 'FAIL'}] baseline persisted + "
          f"decrypted ({reloaded} events)")

    ok = (a["score"] > b["score"] and a["level"] in ("high", "critical")
          and b["level"] == "low" and reloaded >= 60)
    print("\nSummary:", "ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    print("behavior.py is a library. Run with --selftest to exercise it.")
