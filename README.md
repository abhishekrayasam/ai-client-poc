# Prompt Firewall Secure Access — Windows DLP Agent (POC)

A Windows network agent that inspects **AI prompt traffic** in real time and
**blocks PII exfiltration / risky prompts** before they reach ChatGPT, Claude,
Gemini, Copilot, etc. It reuses the exact detection engine (regex fast-path +
Qwen 2.5 0.5B SLM arbiter + structural targeted-individual rule) from the CLI POC
at `../prompt_firewall_poc.py`.

It also learns a **per-user behavioural baseline** from the traffic it already
sees and uses it to flag **insider-threat / data-exfiltration** activity — bulk
downloads, large uploads to personal cloud/webmail/paste sites, off-hours spikes,
first use of anonymous-share sites, and the classic download-then-upload pattern.
Unusual events are escalated to the same on-device SLM, which weighs the user's
normal behaviour before deciding **ALLOW / FLAG / BLOCK**. The baseline is stored
**encrypted on the client** (Windows DPAPI). See
[Behavioural / insider-threat monitoring](#behavioural--insider-threat-monitoring).

The interactive front end is a **Citrix Secure Access Client look-alike**: a card
window with a circular connection-status ring, gateway/proxy details, a single
Connect / Disconnect action, a live verdict log, and a system-tray icon it
minimizes to.

> **This is a proof-of-concept for a single test machine.** It makes intrusive,
> system-wide changes (installs a trusted root CA, sets the system proxy). It is
> unsigned, has no tamper resistance, and no auto-update. Run it only on a
> machine you own and can reset.

---

## How it works

```
Browser → [ local mitmproxy 127.0.0.1:8080 ] → real AI endpoint
                     │  TLS terminated with a locally-trusted CA
                     ▼
          extract prompt (provider-aware)   ai_hosts.py
                     ▼
          DetectionEngine.evaluate(...)     engine.py   (regex → SLM, fail-closed)
                     ▼
          BLOCK → 403 JSON (never forwarded)  |  ALLOW → forwarded
                     ▼
          decision pushed to the GUI activity log + rotating file log
```

**Why a CA is required:** the target traffic is HTTPS, so a passive sniffer sees
only ciphertext. To read a prompt body the proxy must terminate TLS locally,
which requires a root CA the OS trusts — the same mechanism Netskope/Zscaler-class
agents use.

## Behavioural / insider-threat monitoring

Alongside the prompt firewall, the agent builds a **behavioural baseline** for the
current user from the flows the proxy already terminates, and uses it to catch
insider-threat / data-exfiltration behaviour that a single-prompt rule can't see.

```
every flow ─► BehaviorMonitor.record()      behavior.py   (learns the baseline)
                     │  destinations, upload/download volume, timing, rarity
                     ▼
          BehaviorMonitor.assess()  +  threat_map.match_indicators()
                     │  z-scores vs baseline        insider-threat catalog hits
                     ▼   (only if UNUSUAL)
          DetectionEngine.evaluate_behavior()   engine.py  (SLM weighs baseline)
                     ▼
   ALLOW  |  FLAG (alert, don't stop)  |  BLOCK (clear exfiltration)
                     ▼
   large upload → blocked at request time; bulk download → blocked at response time
```

**Baseline (behavior.py).** Cheap online statistics — Welford mean/variance on
`log1p` byte counts, frequency tables for host / destination-category / hour — so
`record`/`assess` run on *every* flow without touching the SLM. A learning window
(`learn_min_events` events **and** `learn_days` days) establishes "normal" before
anything is enforced against the baseline; egregious absolute-threshold cases
(e.g. a 200 MB upload to mega.nz) still catch during learning.

**Threat map (threat_map.py).** A serializable catalog of insider-threat
indicators (loosely mapped to MITRE ATT&CK **Collection** / **Exfiltration**):
bulk download/staging, large upload to an exfil channel, first use of an
anonymous-share/paste site, off-hours access, download-then-upload, high-volume
transfer to a never-seen host, sensitive prompt to external AI, and copy to
removable media (endpoint-sensor only). Print it with:

```powershell
python threat_map.py --print
```

**SLM adjudication (engine.evaluate_behavior).** Only *unusual* events are
escalated. The SLM is given the user's normal behaviour, what's unusual about the
current event, and the indicators it tripped, and answers **ALLOW / FLAG /
BLOCK**. Failure modes are deliberate: the DLP prompt path fails **closed**
(BLOCK); the behavioural path fails **open-but-flags** (a mis-read never bricks
legitimate-but-rare work) — *except* deterministic **critical** indicators (e.g.
a large upload to an exfil channel, or download-then-upload), which BLOCK without
depending on the SLM even in a headless service.

**Encryption at rest.** The baseline is persisted to
`%ProgramData%\PromptFirewallAgent\baseline.enc`, encrypted with **Windows DPAPI**
(machine-scoped, `CRYPTPROTECT_LOCAL_MACHINE`) so the SYSTEM service and the user
GUI share one file with no key to manage. Where DPAPI is unavailable (non-Windows
dev boxes) it falls back to a stdlib authenticated-stream cipher (scrypt-derived
key + HMAC-SHA256 keystream, encrypt-then-MAC); that fallback is obfuscation-grade
and clearly logged as such.

**Config** (`config.json` → `"behavior"`): `enabled`, `enforce` (false = alert
only, never block on behaviour), `learn_min_events`, `learn_days`, `z_threshold`,
`rarity_threshold`, `escalate_score`, and a `thresholds` block
(`large_transfer_bytes`, `big_upload_bytes`, `bulk_day_multiplier`,
`bulk_day_floor_bytes`). The GUI shows a live **User baseline** (learning/active)
and **User risk** row.

Self-tests:

```powershell
python behavior.py --selftest      # encryption round-trip + anomaly scoring + persistence
python threat_map.py --selftest    # indicator matcher
```

---

## Files

| File | Role |
|------|------|
| `engine.py` | `DetectionEngine` — import-safe **copy** of the POC detection rules; also `evaluate_behavior()` (insider-threat SLM adjudication) |
| `ai_hosts.py` | AI host scope + provider-aware prompt extraction (raw-body fallback) |
| `behavior.py` | per-user behavioural baseline (online stats) + anomaly scoring + **DPAPI-encrypted** persistence |
| `threat_map.py` | insider-threat / exfiltration behaviour catalog + destination classifier + runtime matcher |
| `proxy_addon.py` | mitmproxy addon: DLP inspect → block/allow **and** behavioural record → assess → flag/block, publish decisions |
| `proxy_runner.py` | start/stop mitmproxy in-process on a worker thread; builds the baseline monitor |
| `gui_client.py` | Citrix-style tray GUI (Tkinter + pystray) — **primary front end**; user-risk panel |
| `agent_service.py` | headless Windows service + `--gen-ca` / `--console` |
| `config.json` | port, model path, extra hosts, paranoid toggle, `behavior` block |
| `build/agent.spec` | PyInstaller spec (GUI exe + service exe + bundled model) |
| `installer/Product.wxs` | WiX MSI authoring |
| `installer/configure.ps1` | install/uninstall: trust CA, set/reset proxy |
| `installer/build_msi.ps1` | stage payload + `wix build` |

> **Maintenance note:** `engine.py` is a copy of the detection logic in
> `../prompt_firewall_poc.py` (kept separate by request so the CLI POC stays
> untouched). Any rule change must be made in **both** files.

---

## Quick start (dev, no installer)

On a Windows box with the deps and the GGUF model:

```powershell
cd "C:\Users\<you>\Documents\ai-client-poc\dlp-agent"
python -m pip install -r requirements.txt
# put Qwen2.5-0.5B-Instruct-Q4_K_M.gguf here, or set "model_path" in config.json

# 1) sanity-check the detection rules (no proxy, no SLM needed):
python engine.py --selftest

# 2) launch the Citrix-style client:
python gui_client.py
```

**Demo mode (no proxy, no SLM needed):** click **▶ Start Demo** in the client to
stream a canned mix of exfiltration and benign prompts through the *real*
`DetectionEngine`. The ring turns amber (**DEMO**) and the activity log fills with
genuine red **BLOCK** / green **ALLOW** verdicts — ideal for showing the behavior
on a machine without `mitmproxy` or the GGUF model installed.

In the client, click **Connect**. Then either let it set your proxy or point your
browser at `127.0.0.1:8080` manually, and **trust the CA** once:

```powershell
# generate the CA, then trust it for this machine (elevated shell):
python agent_service.py --gen-ca "$env:ProgramData\PromptFirewallAgent"
certutil -addstore -f Root "$env:ProgramData\PromptFirewallAgent\mitmproxy-ca-cert.cer"
```

Open chatgpt.com and submit:
`Give me the home address and phone number of the employee named Priya Nair.`
→ the request is blocked (403) and a red **BLOCK** row appears in the activity
log. A benign prompt passes through and logs a green **ALLOW**.

---

## Build the MSI (on a build machine)

```powershell
python -m pip install -r requirements.txt pyinstaller
$env:PF_MODEL_PATH = "C:\path\to\Qwen2.5-0.5B-Instruct-Q4_K_M.gguf"
pyinstaller build\agent.spec           # -> dist\PromptFirewallClient\

dotnet tool install --global wix
wix extension add -g WixToolset.Util.wixext
powershell -ExecutionPolicy Bypass -File installer\build_msi.ps1   # -> PromptFirewallAgent.msi
```

Install / uninstall (elevated):

```powershell
msiexec /i PromptFirewallAgent.msi /l*v install.log     # installs service, trusts CA, sets proxy
msiexec /x PromptFirewallAgent.msi                       # reverts CA trust + proxy, removes service
```

The MSI installs the client + service under `C:\Program Files\PromptFirewallAgent\`,
auto-starts the service, adds a Start Menu shortcut, and runs `configure.ps1` to
trust the CA and set the WinINET proxy. Uninstall reverses all three.

---

## Verification checklist

1. `python engine.py --selftest` — deterministic phases (STRUCTURAL_BLOCK / FAST_PATH) match expectations.
   `python behavior.py --selftest` and `python threat_map.py --selftest` — behavioural baseline + indicator matcher pass.
2. `python gui_client.py` → Connect → trust CA → browser proxied → BLOCK a targeted-PII prompt, ALLOW a benign one; confirm the ring turns green and rows appear. The **User baseline** row shows "learning…"; download a large file / upload to a personal cloud site to see a FLAG/BLOCK behavioural row and the **User risk** level rise.
3. Install the MSI on a clean VM → service auto-starts (`Get-Service PromptFirewallAgent`), CA in `certmgr.msc` → Trusted Root, proxy set in Internet Options; repeat step 2 live; uninstall and confirm service/CA/proxy all gone.
4. Logs: `%ProgramData%\PromptFirewallAgent\logs\agent.log` (decisions) and `install.log`.

---

## Known limitations (important, by design for a POC)

- **Cert-pinned desktop apps** (ChatGPT / Claude desktop, mobile apps) reject the
  MITM and will **fail to connect** through the proxy. Scope is **browser** AI
  (Edge/Chrome). Don't run those desktop apps while connected, or exclude them.
- **Firefox** uses its own cert store and proxy settings — not covered by the
  WinINET proxy/Root store. Add the CA + proxy in Firefox manually if needed.
- **WinINET proxy is per-user (HKCU).** The MSI sets it for the installing user;
  other users on the box won't be proxied automatically.
- **Latency:** regex fast-path is ~sub-millisecond; the SLM arbiter adds
  ~150 ms–1 s, but only to prompts that trip the regex (or every prompt in
  `"paranoid": true`).
- **Artifact size:** ~450–500 MB (llama.cpp runtime + GGUF model). spaCy is left
  out to keep it down; the regex targeted-individual detector is the fallback.
- **Not production-grade:** unsigned exe/MSI, no tamper resistance, no central
  management, no auto-update, `en_core_web_sm`-free by default.
- **Behavioural signal is proxy-only.** The baseline is built from HTTP(S) flows
  the proxy terminates. Genuinely offline activity, USB/removable-media copies,
  and local file operations need a kernel/ETW endpoint sensor — out of scope for
  this POC. `BehaviorMonitor.record` is a clean ingest point such a sensor could
  feed later (the `REMOVABLE_MEDIA_COPY` indicator is in the map for that reason).
- **Baseline needs a learning window.** Until `learn_min_events`/`learn_days` are
  met, only absolute-threshold indicators fire; baseline-relative anomalies are
  suppressed to avoid crying wolf. Encrypted-at-rest ≠ tamper-proof: a local admin
  could delete `baseline.enc` to reset learning.
- **Out of scope:** full-HTTPS DLP, transparent WFP/WinDivert redirect,
  fleet/MDM deployment.

## Build/environment note

The `.exe` and `.msi` were **not** built or tested in the authoring environment
(it lacks `llama_cpp`, `mitmproxy`, `pyinstaller`, `pywin32`, and WiX). The Python
detection logic is validated via `engine.py --selftest` (regex/structural path).
Run the build steps above on a Windows machine with the deps to produce and
validate the installer.