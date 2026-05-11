# apk-wooper — web APK Wooper (Flask + Monaco)

Password-protected dashboard: upload an APK, run **JADX** (and optional **Apktool**), browse output in a Monaco editor.

## Setup

1. Python 3.10+ recommended.
2. **First-run bootstrap** — creates `.venv`, installs deps, and generates `.env` with a random `SECRET_KEY` and a hashed admin password:

   - Windows (PowerShell or CMD):

     ```bat
     build.bat
     ```

     or

     ```powershell
     .\build.ps1
     ```

   - Linux / macOS:

     ```bash
     ./build.sh
     ```

   The generated dashboard password is printed once and also written to `.admin_password.txt` (gitignored). Save it to a password manager, then delete that file. Re-run with `--force` / `-Force` to rotate the secret and password. Pass `--with-tools` / `-WithTools` to also download JADX + Apktool now.

3. Install a **JDK 11+** (17+ recommended). The app scans common install locations; override with **`JAVA_EXECUTABLE`** in `.env` if needed.

4. Tools: the build script can fetch them with `--with-tools` / `-WithTools`, or you can run **`scripts/bootstrap_tools.ps1`** (Windows) / **`scripts/bootstrap_tools.sh`** (Linux/macOS) directly. Otherwise leave **`AUTO_DOWNLOAD_TOOLS=true`** (default) so missing JADX/Apktool are downloaded into **`tools/`** on startup.

## Run

Activate the virtualenv created by the build script, then start the app:

- Windows: `.\.venv\Scripts\Activate.ps1`
- Linux / macOS: `source .venv/bin/activate`

```bash
python -m apk_web
```

Open `http://127.0.0.1:5000` (set **`HOST`/`PORT`** in `.env` if needed).

## Analysis engine

Every upload goes through three phases: **JADX decompile → Apktool decode → static analysis**. The engine writes its results to `workspaces/<job_id>/analysis/{findings.json,summary.json}` and exposes them through the **Analysis** tab in the dashboard.

### What it detects

| Category | Examples |
| --- | --- |
| Secrets | Firebase / Google API keys, FCM server keys, OpenAI / Anthropic / Stripe / AWS / Slack / GitHub / Twilio / SendGrid / Mapbox tokens, JWTs, PEM private keys |
| Network | HTTP(S) and WebSocket URLs, Retrofit/OkHttp `baseUrl()`, non-private IPv4 |
| Manifest | `debuggable=true`, `allowBackup=true`, `usesCleartextTraffic=true`, exported components without permission, deeplink schemes, dangerous permissions, weak custom permissions |
| Crypto | `AES/ECB` mode, DES/RC4/Blowfish, MD5/SHA1, hardcoded `SecretKeySpec` keys, trust-all TLS managers |
| Auth | Hardcoded `Authorization: Basic` and `Bearer` literals, OAuth `redirect_uri` |
| SDK | Firebase, Crashlytics, OneSignal, Adjust, AppsFlyer, Branch, Mixpanel, Amplitude, Facebook, AppLovin, Sentry DSNs, Supabase project URLs |
| Google services | Keys discovered in `res/values/strings.xml` and `google-services.json` |
| Native | Per `.so`: arch + bits, `DT_NEEDED` libs, interesting `Java_*` / encrypt / decrypt / license exports, plus secrets + URLs recovered from extracted ASCII / UTF-16LE strings |

### Severity levels

- **high** — high-confidence exploitable finding (live AWS key, debuggable app, AES/ECB usage)
- **medium** — strong indicator that may need review (JWT in source, exported component, weak cipher)
- **low** — informational network/permission signal
- **info** — SDK presence, ELF metadata

### Re-running & exports

The **Analysis** tab provides:

- A `Re-run analysis` button (POSTs to `/api/jobs/<id>/analysis`) with a live progress bar
- Filters by severity, category, and free-text search
- One-click jump to the matched line in the Monaco editor with the line and match highlighted
- Exports as `JSON`, `CSV`, or `SARIF v2.1.0` via `GET /api/jobs/<id>/analysis/export?format=json|csv|sarif`

### Optional secret scanners

Three external tools can be enabled from the **Settings → Analysis engine extras** panel (or via env flags):

| Tool | Flag | Notes |
| --- | --- | --- |
| Gitleaks | `ENABLE_GITLEAKS=1` | Auto-installable from the Settings UI (downloads from upstream GitHub releases into `tools/gitleaks/`) |
| TruffleHog | `ENABLE_TRUFFLEHOG=1` | Auto-installable; verified findings are bumped to high severity |
| radare2 | `ENABLE_RADARE2=1` | Auto-installable on Windows from the official portable ZIP into `tools/radare2/`; also works with any `r2` already on `PATH`; enriches `.so` analysis with imports/exports |

Toggles take effect from the next analysis run (use **Re-run analysis** to apply immediately).

### Tuning

| Env var | Default | Purpose |
| --- | --- | --- |
| `ENABLE_ANALYSIS` | `true` | Master switch for the analysis pipeline |
| `ANALYSIS_AUTO_RUN` | `true` | Run analysis automatically after each decompile |
| `ANALYSIS_WORKERS` | `max(2, cpu_count // 2)` | Thread-pool size for file scanners |
| `ANALYSIS_TIMEOUT_SEC` | `600` | Wall-clock budget per run (flushes partial results on timeout) |
| `ANALYSIS_TEXT_MAX_BYTES` | `5 MB` | Per-file cap for text scanners |
| `ANALYSIS_BINARY_MAX_BYTES` | `200 MB` | Per-file cap for `.so` scanners |

## Plugins

The dashboard supports **plugins** — small Flask blueprints (or whole Flask apps) mounted under `/plugins/<id>`. They appear in the sidebar "Plugins" panel and on a dedicated `/plugins` index page. Built-in plugins live under `apk_web/plugins/<id>/`; external plugins are listed in `plugins.json` (path overridable via `PLUGINS_CONFIG`).

### Built-in plugins

| ID | Description |
| --- | --- |
| `firebase` | Test Firebase Realtime Database endpoints discovered in decompiled APKs: connection check, full DB dump, restore from JSON, run custom REST requests, and generate copy-pasteable XSS payloads (LocalStorage dump, keylogger, fake login overlay, BeEF hook). |

### `plugins.json`

```json
{
  "enabled": [],
  "disabled": [],
  "external": [
    {
      "id": "gmap",
      "name": "Google Maps Toolkit",
      "external_path": "C:\\Users\\p\\Documents\\repo\\xss_vulnerability_scanner",
      "module": "gmap_web",
      "factory": "create_app",
      "mode": "iframe",
      "accepts": ["secret.google_api_key", "secret.mapbox_access_token"]
    }
  ]
}
```

External entries can take three shapes:

| Field combination | Mount strategy | When to use |
| --- | --- | --- |
| `module` + `blueprint_attr` | `app.register_blueprint(bp, url_prefix="/plugins/<id>")` | The third-party package exposes a Flask Blueprint. |
| `module` + `factory` (+ optional `factory_kwargs`) | The factory is called and its returned Flask app is mounted under `/plugins/<id>/_app/` via `DispatcherMiddleware`, gated by the dashboard's login session. | The third-party project is a full standalone Flask app (it has a `create_app()` and depends on `app.config[...]`). This is the path that lets you reuse `gmap_web` unchanged. |
| `external_path` only | Loader imports `<external_path>/plugin.py` (must expose a `PLUGIN` object). | One-off external folder you don't want to install as a real package. |

In all cases:

* `external_path` is prepended to `sys.path` so `module` becomes importable without `pip install`.
* `mode` is `native` (the plugin paints onto the APK Wooper chrome by extending `plugins/plugin_base.html`) or `iframe` (the wrapper page shows the plugin in an iframe — recommended for `factory` mounts and any plugin with its own base template).
* `accepts` is a list of Analysis `rule_id`s. Findings whose rule matches one of those get an **"Open in plugin"** button on the finding card that navigates to `/plugins/<id>?prefill=<base64 JSON>` with the matched value pre-filled.

### Built-in plugin manifest

A built-in plugin is just a folder under `apk_web/plugins/<id>/` containing a `plugin.py` that exposes a top-level `PLUGIN`:

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
    mode="native",            # or "iframe"
    accepts=["secret.openai"],
    blueprint=bp,
)
```

The blueprint is mounted at `/plugins/myplug`. Templates living in `apk_web/plugins/myplug/templates/myplug/index.html` are picked up automatically; extend `plugins/plugin_base.html` to get the "Back to jobs" header for free.

### Settings UI

Open Settings → **Plugins** to:

* See every loaded plugin (with source, version, URL, mode).
* Remove an external entry from `plugins.json`.
* Add a new external entry via a small form (writes to `plugins.json` and surfaces a "restart required" hint — the server must restart to actually load a newly-added external plugin).

### Toggling the system off

Set `ENABLE_PLUGINS=0` to skip plugin discovery entirely (useful in tests or hostile environments).

## Tests

```bash
pytest tests/test_apk_web.py tests/analysis tests/plugins -v
```
