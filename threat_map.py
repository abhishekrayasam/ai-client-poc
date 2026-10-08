"""
Insider-threat / data-exfiltration behaviour map.

A catalog of behaviours that, in context, indicate collection or exfiltration
of data by an insider, plus the logic to match a proxy event (combined with the
user's behavioural snapshot from behavior.py) against them.

The catalog is deliberately data-first: ``INDICATOR_CATALOG`` is a plain,
serializable list (id / name / tactic / severity / description / example) so it
can be printed for review, shipped in docs, AND fed to the SLM as context when
it adjudicates an unusual access request. ``match_indicators`` layers the
runtime predicates on top.

Tactics loosely follow MITRE ATT&CK Collection (TA0009) and Exfiltration
(TA0010) so the map lines up with how SOC teams already think.
"""

import logging
from typing import Any, Dict, List, Set

import ai_hosts

log = logging.getLogger("promptfirewall.threatmap")

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# =============================================================================
# Destination classification (used to build events and to match indicators)
# =============================================================================
_CLOUD_STORAGE = (
    "drive.google.com", "docs.google.com", "dropbox.com", "dropboxusercontent.com",
    "box.com", "onedrive.live.com", "1drv.ms", "sharepoint.com",
    "wetransfer.com", "mega.nz", "mega.io", "mediafire.com",
    "s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net",
    "icloud.com",
)
_WEBMAIL = (
    "mail.google.com", "outlook.live.com", "outlook.office.com", "outlook.office365.com",
    "mail.yahoo.com", "mail.proton.me", "protonmail.com", "mail.aol.com", "gmx.com",
)
_CODE_HOST = (
    "github.com", "gitlab.com", "bitbucket.org", "dev.azure.com",
)
_PASTE_SHARE = (
    "pastebin.com", "gist.github.com", "hastebin.com", "ghostbin.com",
    "controlc.com", "paste.ee", "0bin.net", "privatebin.net", "termbin.com",
    "transfer.sh", "file.io", "anonfiles.com", "gofile.io",
)
_REMOVABLE = ("usb", "removable", "external-drive")  # for endpoint-sensor events


def _suffix_match(host: str, suffixes) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s) or s in host for s in suffixes)


def classify_destination(host: str) -> str:
    """Bucket a host into a risk-relevant destination category."""
    if not host:
        return "generic"
    if ai_hosts.is_ai_host(host):
        return "ai"
    if _suffix_match(host, _PASTE_SHARE):
        return "paste_share"
    if _suffix_match(host, _CLOUD_STORAGE):
        return "cloud_storage"
    if _suffix_match(host, _WEBMAIL):
        return "webmail"
    if _suffix_match(host, _CODE_HOST):
        return "code_host"
    return "generic"


# Destination categories that are plausible *exfiltration channels* when a lot
# of data flows *out* to them.
EXFIL_CHANNELS = ("cloud_storage", "webmail", "paste_share", "ai")


# =============================================================================
# The behaviour map (serializable; safe to print / send to the LLM)
# =============================================================================
INDICATOR_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "BULK_DOWNLOAD",
        "name": "Bulk data download / staging",
        "tactic": "Collection",
        "severity": "high",
        "description": "A single response, or the day's cumulative download, is "
                       "far larger than the user's norm - consistent with staging "
                       "data before exfiltration.",
        "example": "Pulling a 4 GB export from an internal app when the user "
                   "normally downloads a few MB a day.",
    },
    {
        "id": "LARGE_UPLOAD_EXFIL_CHANNEL",
        "name": "Large upload to an exfiltration channel",
        "tactic": "Exfiltration",
        "severity": "critical",
        "description": "A large request body sent to personal cloud storage, "
                       "webmail, a paste/anonymous-share site, or an AI endpoint.",
        "example": "Uploading a 200 MB archive to mega.nz or attaching a customer "
                   "list to personal Gmail.",
    },
    {
        "id": "NEW_EXFIL_CHANNEL",
        "name": "First use of an anonymous share / paste site",
        "tactic": "Exfiltration",
        "severity": "high",
        "description": "Traffic to a paste or anonymous file-transfer service the "
                       "user has never used before - common ad-hoc exfil route.",
        "example": "First-ever POST to transfer.sh or pastebin.com.",
    },
    {
        "id": "OFF_HOURS_ACTIVITY",
        "name": "Off-hours data access",
        "tactic": "Collection",
        "severity": "medium",
        "description": "Meaningful data transfer at an hour well outside the "
                       "user's established active window.",
        "example": "Large downloads at 3am from an account that is normally 9-6.",
    },
    {
        "id": "STAGE_THEN_EXFIL",
        "name": "Download-then-upload (stage then exfil)",
        "tactic": "Exfiltration",
        "severity": "critical",
        "description": "A spike in downloads followed the same day by a large "
                       "upload to an external channel - the classic collect-then-"
                       "exfiltrate pattern.",
        "example": "Bulk export from a CRM in the morning, big upload to Dropbox "
                   "in the afternoon.",
    },
    {
        "id": "RARE_DESTINATION_VOLUME",
        "name": "High-volume transfer to a never-seen destination",
        "tactic": "Exfiltration",
        "severity": "high",
        "description": "Substantial data moving to a host the user has never "
                       "contacted before.",
        "example": "First contact with an unknown domain that immediately receives "
                   "tens of MB.",
    },
    {
        "id": "SENSITIVE_TO_EXTERNAL_AI",
        "name": "Sensitive content pasted into external AI",
        "tactic": "Exfiltration",
        "severity": "high",
        "description": "A large or PII-bearing prompt sent to an external AI "
                       "endpoint (pairs with the DLP prompt scanner).",
        "example": "Pasting an internal document dump into ChatGPT.",
    },
    {
        "id": "REMOVABLE_MEDIA_COPY",
        "name": "Copy to removable media",
        "tactic": "Exfiltration over Physical Medium",
        "severity": "high",
        "description": "Large file copy to USB/removable storage. Requires an "
                       "endpoint sensor to observe - included in the map for "
                       "completeness; not detectable from proxy traffic alone.",
        "example": "Dragging a project folder onto a USB stick.",
    },
]

# id -> catalog entry, for enrichment.
_BY_ID = {e["id"]: e for e in INDICATOR_CATALOG}


def catalog_for_llm() -> List[Dict[str, str]]:
    """Trimmed catalog to embed in the SLM prompt (id/name/severity/desc)."""
    return [{"id": e["id"], "name": e["name"], "severity": e["severity"],
             "tactic": e["tactic"], "description": e["description"]}
            for e in INDICATOR_CATALOG]


# =============================================================================
# Runtime matching
# =============================================================================
# Absolute floors so a brand-new baseline (still learning) can still catch the
# egregious cases. Tunable via config -> behavior.thresholds.
DEFAULTS = {
    "large_transfer_bytes": 50 * 1024 * 1024,        # 50 MB single transfer
    "big_upload_bytes": 20 * 1024 * 1024,            # 20 MB upload
    "bulk_day_multiplier": 3.0,                       # day vs typical day
    "bulk_day_floor_bytes": 500 * 1024 * 1024,       # 500 MB/day absolute floor
}


def _hit(ind_id: str, detail: str) -> Dict[str, Any]:
    e = _BY_ID[ind_id]
    return {"id": ind_id, "name": e["name"], "tactic": e["tactic"],
            "severity": e["severity"], "detail": detail}


def match_indicators(event: Dict[str, Any], snapshot: Dict[str, Any],
                     thresholds: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Return the threat-map indicators an event trips, given the user snapshot.

    ``event`` fields used: host, category, hour, req_bytes, resp_bytes,
    has_prompt, prompt_flagged, source ("proxy"|"endpoint"), media.
    ``snapshot`` comes from BehaviorMonitor.snapshot().
    """
    t = dict(DEFAULTS)
    if thresholds:
        t.update({k: v for k, v in thresholds.items() if v is not None})

    hits: List[Dict[str, Any]] = []
    host = event.get("host", "")
    category = event.get("category") or classify_destination(host)
    req = int(event.get("req_bytes", 0) or 0)
    resp = int(event.get("resp_bytes", 0) or 0)
    hour = event.get("hour")
    known_hosts: Set[str] = snapshot.get("known_hosts", set())
    active_hours: Set[str] = {str(h) for h in snapshot.get("active_hours", set())}

    # Bulk download (single transfer or cumulative day).
    if resp >= t["large_transfer_bytes"]:
        hits.append(_hit("BULK_DOWNLOAD",
                         f"{resp/1e6:.0f}MB single download from {host}"))
    day_dl = snapshot.get("session_download_bytes", 0)
    typ_dl = snapshot.get("typical_daily_download_bytes", 0)
    if day_dl >= t["bulk_day_floor_bytes"] or (
            typ_dl > 0 and day_dl > t["bulk_day_multiplier"] * typ_dl):
        hits.append(_hit("BULK_DOWNLOAD",
                         f"cumulative {day_dl/1e6:.0f}MB downloaded today"))

    # Large upload to an exfil channel.
    if req >= t["big_upload_bytes"] and category in EXFIL_CHANNELS:
        hits.append(_hit("LARGE_UPLOAD_EXFIL_CHANNEL",
                         f"{req/1e6:.0f}MB uploaded to {category} ({host})"))

    # First use of a paste / anonymous-share site.
    if category == "paste_share" and host and host not in known_hosts:
        hits.append(_hit("NEW_EXFIL_CHANNEL", f"first use of {host}"))

    # High-volume transfer to a never-seen destination.
    if host and host not in known_hosts and (req + resp) >= t["large_transfer_bytes"]:
        hits.append(_hit("RARE_DESTINATION_VOLUME",
                         f"{(req+resp)/1e6:.0f}MB to new host {host}"))

    # Off-hours meaningful transfer.
    if (hour is not None and active_hours and str(hour) not in active_hours
            and (req + resp) >= t["big_upload_bytes"]):
        hits.append(_hit("OFF_HOURS_ACTIVITY",
                         f"{(req+resp)/1e6:.0f}MB at {hour}:00, outside active hours"))

    # Stage-then-exfil: big day download AND a big upload to a channel now.
    if (req >= t["big_upload_bytes"] and category in EXFIL_CHANNELS
            and day_dl >= t["bulk_day_floor_bytes"]):
        hits.append(_hit("STAGE_THEN_EXFIL",
                         f"{day_dl/1e6:.0f}MB downloaded today then "
                         f"{req/1e6:.0f}MB uploaded to {host}"))

    # Sensitive/large prompt to external AI.
    if event.get("has_prompt") and category == "ai" and (
            event.get("prompt_flagged") or req >= t["big_upload_bytes"]):
        why = "PII-flagged prompt" if event.get("prompt_flagged") else \
              f"{req/1e6:.0f}MB prompt"
        hits.append(_hit("SENSITIVE_TO_EXTERNAL_AI", f"{why} to {host}"))

    # Endpoint-sensor: copy to removable media (only if such events are fed in).
    if event.get("source") == "endpoint" and str(event.get("media", "")).lower() in _REMOVABLE:
        hits.append(_hit("REMOVABLE_MEDIA_COPY",
                         f"{(req)/1e6:.0f}MB copied to {event.get('media')}"))

    return hits


def max_severity(hits: List[Dict[str, Any]]) -> str:
    if not hits:
        return "none"
    return max((h["severity"] for h in hits), key=lambda s: SEVERITY_ORDER[s])


# =============================================================================
# Self-test / print the map:  python threat_map.py --selftest | --print
# =============================================================================
def _print_map() -> int:
    print("\nInsider-threat / exfiltration behaviour map\n" + "=" * 60)
    for e in INDICATOR_CATALOG:
        print(f"\n[{e['severity'].upper():8}] {e['id']}  ({e['tactic']})")
        print(f"  {e['name']}")
        print(f"  {e['description']}")
        print(f"  e.g. {e['example']}")
    return 0


def _selftest() -> int:
    logging.basicConfig(level=logging.INFO)
    snap = {
        "known_hosts": {"github.com", "docs.python.org", "mail.google.com"},
        "active_hours": {"9", "10", "11", "12", "13", "14", "15", "16", "17"},
        "session_download_bytes": 0,
        "typical_daily_download_bytes": 5 * 1024 * 1024,
    }
    cases = [
        ("benign browse", {"host": "github.com", "category": "code_host",
                           "hour": 10, "req_bytes": 1500, "resp_bytes": 30_000}, []),
        ("bulk download", {"host": "intranet.corp", "category": "generic",
                           "hour": 11, "req_bytes": 800, "resp_bytes": 4_000_000_000},
         ["BULK_DOWNLOAD", "RARE_DESTINATION_VOLUME"]),
        ("upload to mega", {"host": "mega.nz", "category": "cloud_storage",
                            "hour": 11, "req_bytes": 200_000_000, "resp_bytes": 500},
         ["LARGE_UPLOAD_EXFIL_CHANNEL", "RARE_DESTINATION_VOLUME"]),
        ("paste site", {"host": "pastebin.com", "category": "paste_share",
                        "hour": 11, "req_bytes": 5000, "resp_bytes": 500},
         ["NEW_EXFIL_CHANNEL"]),
        ("off-hours upload", {"host": "dropbox.com", "category": "cloud_storage",
                              "hour": 3, "req_bytes": 25_000_000, "resp_bytes": 0},
         ["LARGE_UPLOAD_EXFIL_CHANNEL", "OFF_HOURS_ACTIVITY"]),
        ("PII prompt to AI", {"host": "chatgpt.com", "category": "ai", "hour": 11,
                              "req_bytes": 3000, "resp_bytes": 2000,
                              "has_prompt": True, "prompt_flagged": True},
         ["SENSITIVE_TO_EXTERNAL_AI"]),
    ]
    failures = 0
    print("\nThreat-map matcher self-test\n" + "=" * 60)
    for name, ev, expected in cases:
        hits = match_indicators(ev, snap)
        got = {h["id"] for h in hits}
        ok = set(expected).issubset(got)
        if not ok:
            failures += 1
        print(f"[{'PASS' if ok else 'FAIL'}] {name:20s} sev={max_severity(hits):8s} "
              f"-> {sorted(got)}")
        if not ok:
            print(f"        expected superset of {expected}")
    print(f"\n{len(cases) - failures}/{len(cases)} cases passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    import sys
    if "--print" in sys.argv:
        raise SystemExit(_print_map())
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    print("threat_map.py is a library. Use --print to view the map or "
          "--selftest to test the matcher.")
