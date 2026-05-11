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

## Tests

```bash
pytest tests/test_apk_web.py tests/analysis -v
```
