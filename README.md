# apk-wooper

A web dashboard for Android APK analysis. Upload an APK, decompile it with **JADX** (and optionally **Apktool**), browse the output in a Monaco editor, and run a static analysis pipeline that surfaces secrets, network endpoints, manifest issues, crypto weaknesses, and more.

---

## Requirements

| Requirement | Notes |
|---|---|
| **Python 3.12** | Required. The build script locates it automatically and can install it for you if it is missing (see [Setup](#setup)). |
| **JDK 11+** (17+ recommended) | Needed by JADX and Apktool. The app scans common install locations; override with `JAVA_EXECUTABLE` in `.env` if needed. |

---

## Setup

Run the bootstrap script once. It will:

1. Locate (or install) Python 3.12.
2. Create a `.apkwooper` virtual environment.
3. Generate `.env` with a random `SECRET_KEY` and a hashed admin password.
4. Install all dependencies.
5. Download JADX and Apktool (driven by `.env` flags, or immediately with `--with-tools`).
6. Write a `run.sh` / `run.bat` launcher.

**Windows** (PowerShell or CMD):

```bat
build.bat
```

or

```powershell
.\build.ps1
```

**Linux / macOS:**

```bash
./build.sh
```

The generated admin password is printed once and also written to `.admin_password.txt` (gitignored). Save it to a password manager, then delete that file.

### Build flags

| Flag (shell / PowerShell) | Effect |
|---|---|
| `--force` / `-Force` | Rotate `SECRET_KEY` and admin password even if they already exist. |
| `--with-tools` / `-WithTools` | Force-download JADX, Apktool, and any enabled optional tools immediately instead of waiting for first launch. |
| `--with-optional` / `-WithOptional` | Install `requirements-optional.txt` (APKiD, etc.). |
| `--with-mobsf` / `-WithMobSF` | Clone and run MobSF setup during the build. |
| `--skip-tools` / `-SkipTools` | Skip the tool bootstrap step (useful in CI). |
| `--skip-plugins` / `-SkipPlugins` | Skip the plugin bootstrap step. |
| `--no-auto-install-python` / `-NoAutoInstallPython` | Fail with instructions instead of auto-installing Python 3.12. |
| `--python BIN` / `-Python BIN` | Use a specific Python 3.12 interpreter. |

---

## Run

The build script writes a launcher. Use it to start the dashboard:

**Windows:**

```bat
run.bat
```

**Linux / macOS:**

```bash
./run.sh
```

Open `http://127.0.0.1:5000` in your browser. Set `HOST` and `PORT` in `.env` to change the bind address.

---

## Analysis engine

Every upload goes through three phases: **JADX decompile → Apktool decode → static analysis**. Results are written to `workspaces/<job_id>/analysis/{findings.json,summary.json}` and surfaced in the **Analysis** tab.

### What it detects

| Category | Examples |
|---|---|
| Secrets | Firebase / Google API keys, FCM server keys, OpenAI / Anthropic / Stripe / AWS / Slack / GitHub / Twilio / SendGrid / Mapbox tokens, JWTs, PEM private keys |
| Network | HTTP(S) and WebSocket URLs, Retrofit/OkHttp `baseUrl()`, non-private IPv4 |
| Manifest | `debuggable=true`, `allowBackup=true`, `usesCleartextTraffic=true`, exported components without permission, deeplink schemes, dangerous permissions, weak custom permissions |
| Crypto | `AES/ECB` mode, DES/RC4/Blowfish, MD5/SHA1, hardcoded `SecretKeySpec` keys, trust-all TLS managers |
| Auth | Hardcoded `Authorization: Basic` and `Bearer` literals, OAuth `redirect_uri` |
| SDK | Firebase, Crashlytics, OneSignal, Adjust, AppsFlyer, Branch, Mixpanel, Amplitude, Facebook, AppLovin, Sentry DSNs, Supabase project URLs |
| Google services | Keys discovered in `res/values/strings.xml` and `google-services.json` |
| Native | Per `.so`: arch + bits, `DT_NEEDED` libs, interesting `Java_*` / encrypt / decrypt / license exports, plus secrets and URLs recovered from extracted ASCII / UTF-16LE strings |

### Severity levels

| Level | Meaning |
|---|---|
| **high** | High-confidence exploitable finding (live AWS key, debuggable app, AES/ECB usage) |
| **medium** | Strong indicator that may need review (JWT in source, exported component, weak cipher) |
| **low** | Informational network/permission signal |
| **info** | SDK presence, ELF metadata |

### Re-running and exports

The **Analysis** tab provides:

- A **Re-run analysis** button (POSTs to `/api/jobs/<id>/analysis`) with a live progress bar.
- Filters by severity, category, and free-text search.
- One-click jump to the matched line in the Monaco editor with the line and match highlighted.
- Export as **JSON**, **CSV**, or **SARIF v2.1.0** via `GET /api/jobs/<id>/analysis/export?format=json|csv|sarif`.

### Optional secret scanners

Additional analysis tools can be enabled from **Settings → Analysis engine extras** or by setting the corresponding env flag:

| Tool | Flag | Notes |
|---|---|---|
| Gitleaks | `ENABLE_GITLEAKS=1` | Auto-installable from the Settings UI (downloads from upstream GitHub releases into `tools/gitleaks/`). |
| TruffleHog | `ENABLE_TRUFFLEHOG=1` | Auto-installable; verified findings are bumped to high severity. |
| radare2 | `ENABLE_RADARE2=1` | Auto-installable on Windows from the official portable ZIP; also works with any `r2` already on `PATH`. Enriches `.so` analysis with imports/exports. |
| APKiD | `ENABLE_APKID=1` | Pure-Python. The Settings UI offers a one-click install plus a fallback **Install via GitHub source** button for environments where prebuilt wheels are unavailable. Fingerprints packers, obfuscators, anti-VM / anti-debug tricks, and the original compiler on the raw `input.apk`. Refresh signatures occasionally with `apkid -u`. |

Toggles take effect from the next analysis run. Use **Re-run analysis** to apply immediately.

### Tuning

| Env var | Default | Purpose |
|---|---|---|
| `ENABLE_ANALYSIS` | `true` | Master switch for the analysis pipeline. |
| `ANALYSIS_AUTO_RUN` | `true` | Run analysis automatically after each decompile. |
| `ANALYSIS_WORKERS` | `max(2, cpu_count // 2)` | Thread-pool size for file scanners. |
| `ANALYSIS_TIMEOUT_SEC` | `600` | Wall-clock budget per run (flushes partial results on timeout). |
| `ANALYSIS_TEXT_MAX_BYTES` | `5 MB` | Per-file cap for text scanners. |
| `ANALYSIS_BINARY_MAX_BYTES` | `200 MB` | Per-file cap for `.so` scanners. |

---

## Plugins

The dashboard supports **plugins** — Flask blueprints (or standalone Flask apps) mounted under `/plugins/<id>`. They appear in the sidebar **Plugins** panel and on the `/plugins` index page. Built-in plugins live under `apk_web/plugins/<id>/`; external plugins are declared in `plugins.json` (path overridable via `PLUGINS_CONFIG`).

### Built-in plugins

| ID | Description |
|---|---|
| `firebase` | Test Firebase Realtime Database endpoints discovered in decompiled APKs: connection check, full DB dump, restore from JSON, custom REST requests, and copy-pasteable XSS payloads (LocalStorage dump, keylogger, fake login overlay, BeEF hook). |
| `mobsf` | Send the current job's APK to an external [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) instance over REST and embed the report iframe in the dashboard. See [MobSF](#mobsf) below. |

### MobSF

The MobSF plugin does not bundle MobSF itself — APK Wooper talks to a separately-running instance over HTTP. When MobSF is unreachable, `/plugins/mobsf` exposes a **GitHub installer panel** that drives the setup as a normal user process (no admin / root, no Docker):

1. **Clone repo** — `git clone` into `tools/mobsf/` (or `git pull` if already cloned).
2. **Run setup** — runs `setup.sh` / `setup.bat` inside the clone.
3. **Start MobSF** — spawns `run.sh` / `run.bat` as a detached child; the PID and port are persisted in `tools/mobsf/.apk_wooper_mobsf_state.json` so the panel can show running/stopped status across restarts.

**Stop** kills the tracked PID. **Show run.log** tails the last 16 KiB of MobSF's stdout/stderr.

Equivalent manual flow:

```bash
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh   # setup.bat on Windows
./run.sh 127.0.0.1:8000
```

Once MobSF is running, copy the API key from its **Settings → API Docs** page and either paste it into the form at `/plugins/mobsf` or set the env vars below.

| Env var | Default | Purpose |
|---|---|---|
| `ENABLE_MOBSF` | `true` | Show/hide the MobSF toolbar button and `/plugins/mobsf` page. |
| `MOBSF_URL` | `http://localhost:8000` | Base URL of the running MobSF instance. |
| `MOBSF_API_KEY` | _(empty)_ | MobSF API key (sent as the `Authorization` header on every REST call). |

### `plugins.json`

```json
{
  "enabled": [],
  "disabled": [],
  "external": [
    {
      "id": "gmap",
      "name": "Google Maps Toolkit",
      "external_path": "/path/to/gmap_plugin",
      "module": "gmap_web",
      "factory": "create_app",
      "mode": "iframe",
      "accepts": ["secret.google_api_key", "secret.mapbox_access_token"]
    }
  ]
}
```

External entries support three mount strategies:

| Field combination | Mount strategy | When to use |
|---|---|---|
| `module` + `blueprint_attr` | Registers the blueprint at `/plugins/<id>`. | The package exposes a Flask `Blueprint`. |
| `module` + `factory` (+ optional `factory_kwargs`) | Calls the factory and mounts the returned Flask app under `/plugins/<id>/_app/` via `DispatcherMiddleware`, gated by the dashboard login session. | The plugin is a full standalone Flask app. |
| `external_path` only | Imports `<external_path>/plugin.py` which must expose a `PLUGIN` object. | A one-off folder you do not want to install as a package. |

In all cases, `external_path` is prepended to `sys.path` so the module is importable without a `pip install`. Set `mode` to `native` (plugin renders within the APK Wooper chrome) or `iframe` (recommended for factory mounts and plugins with their own base templates). The `accepts` list is a set of analysis `rule_id`s; matching findings get an **"Open in plugin"** action on the finding card.

### Writing a built-in plugin

A built-in plugin is a folder under `apk_web/plugins/<id>/` with a `plugin.py` that exposes a top-level `PLUGIN`:

```python
from flask import Blueprint
from apk_web.plugins.registry import Plugin

bp = Blueprint("myplug", __name__, template_folder="templates")

@bp.route("/")
def index():
    return "hello"

PLUGIN = Plugin(
    id="myplug",
    name="My plugin",
    description="Does a thing.",
    version="1.0.0",
    mode="native",          # or "iframe"
    accepts=["secret.openai"],
    blueprint=bp,
)
```

The blueprint is mounted at `/plugins/myplug`. Templates in `apk_web/plugins/myplug/templates/myplug/` are picked up automatically; extend `plugins/plugin_base.html` to get the standard header for free.

### Settings UI

**Settings → Plugins** lets you:

- View every loaded plugin (source, version, URL, mode).
- Remove an external entry from `plugins.json`.
- Add a new external entry via a form (writes to `plugins.json`; a server restart is required to load the new plugin).

Set `ENABLE_PLUGINS=0` to skip plugin discovery entirely (useful in CI or restricted environments).

---

## Tests

```bash
pytest tests/test_apk_web.py tests/analysis tests/plugins -v
```