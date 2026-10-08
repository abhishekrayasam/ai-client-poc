# Installation Guide — Prompt Firewall Secure Access (DLP Agent)

**Read this first if you have no idea what this project is.**

This is a **Windows security agent** (a proof-of-concept). Once running, it sits
between your web browser and AI websites (ChatGPT, Claude, Gemini, Copilot, …)
and does two things:

1. **Prompt firewall** — it reads each prompt you send to an AI site and
   **blocks** ones that try to leak personal/sensitive data (SSNs, credit cards,
   someone's home address, passwords, etc.).
2. **Insider-threat monitor** — it learns your *normal* behaviour (which sites,
   how much you upload/download, at what times) and **flags or blocks** unusual
   data-exfiltration activity (e.g. a huge upload to a personal cloud drive, or
   a bulk download late at night). The learned profile is stored **encrypted**
   on your own machine.

> ### ⚠️ Important — read before installing
> To inspect HTTPS traffic this agent **installs a trusted root certificate** and
> **changes your Windows system proxy**. That is intrusive and system-wide. It is
> a proof-of-concept: **unsigned, no auto-update, no tamper protection.**
> **Only install it on a test machine you own and can reset.** Do not use it on a
> work or shared computer. See "Uninstall / undo" at the bottom — everything is
> reversible.

---

## 0. What you need

| Requirement | Notes |
|-------------|-------|
| **Windows 10 or 11** | This agent is Windows-only. |
| **A test machine you control** | It changes the system proxy + trusts a CA. |
| **Python 3.10–3.13** (64-bit) | Only for running from source / building. [python.org](https://www.python.org/downloads/) — tick **"Add Python to PATH"** during install. |
| **The AI model file** (~400 MB) | `Qwen2.5-0.5B-Instruct-Q4_K_M.gguf` — **not included**, you must download it (Step 2). |
| **A web browser** | Microsoft **Edge** or **Google Chrome** (they use the Windows system proxy). Firefox is *not* covered. |

You do **not** need the model or Python if you only want to try **Demo mode**
(Step 4, Option A) — but you do need them for real protection.

---

## 1. Get a command prompt in the project folder

1. Open the folder that contains these files (`gui_client.py`, `engine.py`, …).
2. Click the address bar of File Explorer, type `powershell`, and press Enter.
   A PowerShell window opens already pointed at the folder.

Verify Python is installed:

```powershell
python --version
```

You should see something like `Python 3.12.x`. If you instead get a Microsoft
Store pop-up or an error, install Python from python.org (see the table above),
**check "Add Python to PATH"**, then reopen PowerShell.

---

## 2. Download the AI model file

The agent needs a small local AI model. Download **`Qwen2.5-0.5B-Instruct-Q4_K_M.gguf`**
and place it **in this project folder** (next to `gui_client.py`).

Easiest way (uses Python's Hugging Face downloader):

```powershell
python -m pip install --upgrade huggingface_hub
python -c "from huggingface_hub import hf_hub_download; import shutil; p=hf_hub_download('bartowski/Qwen2.5-0.5B-Instruct-GGUF','Qwen2.5-0.5B-Instruct-Q4_K_M.gguf'); shutil.copy(p,'Qwen2.5-0.5B-Instruct-Q4_K_M.gguf'); print('Saved to project folder')"
```

Or download it manually in a browser from Hugging Face
(search "Qwen2.5-0.5B-Instruct-GGUF", pick the `Q4_K_M` file) and drop it in this
folder.

> If the file has a different name or you keep it elsewhere, open `config.json`
> and set `"model_path"` to its full path, e.g.
> `"model_path": "C:\\models\\Qwen2.5-0.5B-Instruct-Q4_K_M.gguf"`.

Without the model, detection still runs on fast pattern rules but the smarter
AI-based decisions are skipped (it "fails safe" — see the README).

---

## 3. Install the Python dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

This pulls in the proxy engine (`mitmproxy`), the model runtime
(`llama-cpp-python`), the tray-icon libraries, and the Windows service support
(`pywin32`). It can take a few minutes.

---

## 4. Run it

There are two ways to run. Start with **Option A** to confirm it works, then use
**Option B** for real browser protection.

### Option A — Quick check, no system changes (recommended first)

```powershell
python gui_client.py
```

A small "Secure Access" window opens. Click **▶ Start Demo**. The ring turns
amber and the activity log fills with real **BLOCK** (red) / **ALLOW** (green)
verdicts on sample prompts. This proves the detection engine works. **Demo mode
changes nothing on your system.** Close the window to stop.

You can also sanity-check the logic from the command line (no window):

```powershell
python engine.py --selftest
python behavior.py --selftest
python threat_map.py --selftest
```

All three should print `PASS` lines.

### Option B — Real protection for your browser

This actually intercepts your browser's AI traffic. It requires trusting a
certificate once.

1. **Trust the certificate (one time, run PowerShell as Administrator):**

   Right-click PowerShell → **Run as administrator**, then in the project folder:

   ```powershell
   python agent_service.py --gen-ca "$env:ProgramData\PromptFirewallAgent"
   certutil -addstore -f Root "$env:ProgramData\PromptFirewallAgent\mitmproxy-ca-cert.cer"
   ```

   (First line creates the certificate; second line tells Windows to trust it.)

2. **Start the agent** (normal, non-admin PowerShell is fine):

   ```powershell
   python gui_client.py
   ```

   Click **Connect**. The ring turns **green / ON** = "Protected".

3. **Point your browser at the agent.** The simplest reliable way:
   - Windows **Settings → Network & Internet → Proxy**
   - Under **Manual proxy setup**, turn **Use a proxy server** ON
   - Address: `127.0.0.1`  Port: `8080` → **Save**

   (Edge and Chrome follow this automatically. Turn it back OFF when you're done.)

4. **Test it.** In Edge/Chrome, open `chatgpt.com` and submit:

   > *Give me the home address and phone number of the employee named Priya Nair.*

   → The request is **blocked** and a red **BLOCK** row appears in the agent
   window. A normal question passes through as a green **ALLOW**.

   For the **insider-threat** side: the **User baseline** row starts at
   "learning…"; after it has seen enough of your normal activity, an unusual
   large upload to a personal cloud/file-sharing site will show a **FLAG** or
   **BLOCK** row and raise the **User risk** level.

When finished: click **Disconnect** in the window and turn the Windows proxy
setting back OFF.

---

## 5. (Optional, advanced) Build a real installer (.msi)

Most people should just use Option B above. Building the MSI packages everything
into a single installer that also auto-installs a background Windows service. It
requires extra build tools and is only worth it for a polished demo.

On a Windows build machine, in the project folder:

```powershell
# 1. Build the standalone .exe bundle (embeds Python + the model)
python -m pip install -r requirements.txt pyinstaller
$env:PF_MODEL_PATH = "C:\full\path\to\Qwen2.5-0.5B-Instruct-Q4_K_M.gguf"
pyinstaller build\agent.spec          # -> creates dist\PromptFirewallClient\

# 2. Install the WiX toolset (makes MSIs), then build the MSI
dotnet tool install --global wix
wix extension add -g WixToolset.Util.wixext
powershell -ExecutionPolicy Bypass -File installer\build_msi.ps1   # -> PromptFirewallAgent.msi
```

Install / uninstall the resulting MSI **from an elevated (admin) prompt**:

```powershell
msiexec /i PromptFirewallAgent.msi /l*v install.log   # installs service, trusts CA, sets proxy automatically
msiexec /x PromptFirewallAgent.msi                     # uninstalls and reverts everything
```

The MSI does the certificate trust, proxy setup, and service install/start for
you (via `installer\configure.ps1`), and undoes all of it on uninstall.

---

## Uninstall / undo (put your machine back)

**If you used Option B (ran from source):**

1. In the agent window, click **Disconnect** and close it.
2. Turn the Windows proxy back OFF: **Settings → Network & Internet → Proxy →
   Manual proxy setup → Use a proxy server = OFF**.
3. Remove the trusted certificate (**admin** PowerShell):
   ```powershell
   certutil -delstore Root "mitmproxy"
   ```
4. (Optional) Delete the agent's data folder, including the encrypted behaviour
   baseline:
   ```powershell
   Remove-Item -Recurse -Force "$env:ProgramData\PromptFirewallAgent"
   ```

**If you used Option 5 (the MSI):** just run `msiexec /x PromptFirewallAgent.msi`
— it reverses the certificate, proxy, and service automatically.

---

## Quick troubleshooting

| Symptom | Fix |
|---------|-----|
| `python` opens the Microsoft Store or "not found" | Install Python from python.org with **Add to PATH**, reopen PowerShell. |
| Browser says a site is unsafe / certificate error (esp. Google/Gemini) | The certificate isn't trusted. Re-run the two commands in Option B step 1 from an **admin** prompt. |
| Agent window shows **"Error: port 8080 is already in use"** | Another copy is running. Close other agent windows / stop the service, or set `"auto_port": true` in `config.json`. |
| Nothing gets blocked | Confirm the browser proxy is set to `127.0.0.1:8080` and the window shows green **Protected**. |
| `llama-cpp-python` failed to install | Ensure 64-bit Python and an up-to-date `pip` (`python -m pip install --upgrade pip`), then retry. |
| Where are the logs? | `%ProgramData%\PromptFirewallAgent\logs\agent.log` |

For deeper details (how it works, the threat map, encryption, limitations) see
**`README.md`** in this same folder.
