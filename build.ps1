# APK Wooper Windows bootstrap.
#
# This script performs a full first-run setup using **Python 3.12**:
#
#   1. Locates a Python 3.12 interpreter (refuses anything else).
#   2. Creates / reuses a virtual environment named `.apkwooper`.
#   3. Generates / updates `.env` with all supported keys (idempotent).
#   4. Installs `requirements.txt`; optionally `requirements-optional.txt`.
#   5. Installs declared built-in plugin pip dependencies.
#   6. Bootstraps tools (JADX, Apktool, and the optional secret scanners
#      when their ENABLE_* flag is true in `.env`).
#   7. Sets up plugins (`plugins.json`, optionally clones MobSF).
#   8. Writes a `run.bat` runner that starts MobSF when ENABLE_MOBSF=true
#      and then launches `python -m apk_web`.
#
# Flags:
#   -Force                  Regenerate SECRET_KEY and admin password even if
#                           they exist.
#   -WithTools              Force the tool bootstrap step (it also runs based
#                           on .env flags, so this is rarely needed).
#   -WithOptional           Install requirements-optional.txt (apkid, etc.).
#   -WithMobSF              Also clone and run MobSF setup during build.
#   -SkipTools              Skip the tool bootstrap step (useful for CI).
#   -SkipPlugins            Skip the plugin bootstrap step.
#   -NoAutoInstallPython    Do not auto-download Python 3.12 when missing;
#                           fail with instructions instead.
#   -Python BIN             Path to a Python 3.12 launcher. Must report 3.12.x.
#
# If Python 3.12 is not found on PATH, the script downloads the official
# python.org Windows installer (per-user, no admin) and silently installs it
# under %LOCALAPPDATA%\Programs\Python\Python312 before continuing.
#
# Examples:
#   .\build.bat
#   .\build.bat -Force
#   .\build.bat -WithOptional -WithMobSF

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$WithTools,
    [switch]$WithOptional,
    [switch]$WithMobSF,
    [switch]$SkipTools,
    [switch]$SkipPlugins,
    [switch]$NoAutoInstallPython,
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Set-Location $Root

$VenvName = ".apkwooper"
$VenvDir  = Join-Path $Root $VenvName
$VenvPy   = Join-Path $VenvDir "Scripts\python.exe"

function Test-IsPython312 {
    param([string]$Exe, [string[]]$Pre)

    try {
        $version = (& $Exe @Pre "-c" "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null).Trim()
    } catch {
        return $null
    }
    if (-not $version) { return $null }
    if ($version -match '^3\.12(\.|$)') {
        return $version
    }
    return $null
}

function Find-Python312Launcher {
    # Returns @{ Exe = ...; Pre = @() } for the first usable Python 3.12, or $null.
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $v = Test-IsPython312 -Exe "py" -Pre @("-3.12")
        if ($v) {
            return @{ Exe = "py"; Pre = @("-3.12"); Version = $v }
        }
    }
    foreach ($cand in @("python3.12", "python3.12.exe", "python", "python3")) {
        if (Get-Command $cand -ErrorAction SilentlyContinue) {
            $v = Test-IsPython312 -Exe $cand -Pre @()
            if ($v) {
                return @{ Exe = $cand; Pre = @(); Version = $v }
            }
        }
    }
    # Also check known per-user / per-machine install layouts even when PATH
    # was not updated (Python.org's installer skips PATH by default for
    # per-user installs).
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312-32\python.exe"),
        "C:\Python312\python.exe",
        "C:\Program Files\Python312\python.exe",
        "C:\Program Files (x86)\Python312\python.exe"
    )
    foreach ($exe in $candidates) {
        if (Test-Path $exe) {
            $v = Test-IsPython312 -Exe $exe -Pre @()
            if ($v) {
                return @{ Exe = $exe; Pre = @(); Version = $v }
            }
        }
    }
    return $null
}

function Install-Python312ViaWinget {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        return $false
    }
    Write-Host ">> Trying winget to install Python 3.12 (per-user, silent)..."
    # Send winget's output to a log file rather than piping through PowerShell.
    # Piping turns winget's animated spinner (carriage-return redraws) into
    # one line per frame, which floods the terminal with garbage like
    # `[winget]    -`, `[winget]    \`, `[winget]    |`, ...
    $logDir = Join-Path $env:TEMP ("apk-wooper-winget-" + [Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $logFile = Join-Path $logDir "winget.log"
    try {
        $proc = Start-Process -FilePath "winget" -ArgumentList @(
            "install", "--id", "Python.Python.3.12", "-e", "--silent",
            "--scope", "user",
            "--accept-package-agreements", "--accept-source-agreements",
            "--disable-interactivity"
        ) -Wait -PassThru -NoNewWindow `
          -RedirectStandardOutput $logFile `
          -RedirectStandardError (Join-Path $logDir "winget.err.log")
        $rc = $proc.ExitCode
    } catch {
        Write-Host "WARNING: winget invocation failed: $($_.Exception.Message)"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $logDir
        return $false
    }
    if ($rc -ne 0) {
        Write-Host "WARNING: winget exited with code $rc; falling back to direct download."
        Write-Host "         (full log: $logFile)"
        # Surface the last few lines so the user sees *why* winget failed.
        try {
            $tail = Get-Content -LiteralPath $logFile -Tail 10 -ErrorAction Stop
            $tail | ForEach-Object { Write-Host "[winget] $_" }
        } catch {}
        return $false
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $logDir
    return $true
}

function Install-Python312FromPythonOrg {
    # Per-user, no-admin install of CPython 3.12.x using the official installer.
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "win32" }
    $pythonVersion = "3.12.7"
    $installerName = "python-$pythonVersion-$arch.exe"
    $url = "https://www.python.org/ftp/python/$pythonVersion/$installerName"

    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("apk-wooper-py312-" + [Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
    $installerPath = Join-Path $tempDir $installerName
    $targetDir = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312"

    Write-Host ">> Downloading Python $pythonVersion installer"
    Write-Host "   $url"
    try {
        # Use TLS 1.2 to satisfy older PowerShell defaults.
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
    } catch {}
    try {
        Invoke-WebRequest -Uri $url -OutFile $installerPath -UseBasicParsing
    } catch {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tempDir
        throw "Could not download $url : $($_.Exception.Message)"
    }

    Write-Host ">> Installing Python $pythonVersion to $targetDir (per-user, silent, no admin)"
    # Per-user install, no admin, do not modify PATH. We'll point at the exact
    # python.exe afterwards so PATH wiring is unnecessary.
    $installerArgs = @(
        "/quiet",
        "InstallAllUsers=0",
        "PrependPath=0",
        "AppendPath=0",
        "Include_launcher=1",
        "InstallLauncherAllUsers=0",
        "Include_pip=1",
        "Include_test=0",
        "Include_doc=0",
        "Include_tcltk=1",
        "TargetDir=$targetDir"
    )
    $proc = Start-Process -FilePath $installerPath -ArgumentList $installerArgs -PassThru -Wait -WindowStyle Hidden
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tempDir

    if ($proc.ExitCode -ne 0) {
        throw "Python installer exited with code $($proc.ExitCode). " +
              "Install Python 3.12 manually from https://www.python.org/downloads/release/python-3127/ and re-run."
    }

    $exe = Join-Path $targetDir "python.exe"
    if (-not (Test-Path $exe)) {
        throw "Installer reported success but $exe was not created."
    }
    Write-Host ">> Python installed at $exe"
    return $exe
}

function Install-Python312 {
    if (Install-Python312ViaWinget) {
        $found = Find-Python312Launcher
        if ($found) { return $found }
        Write-Host "WARNING: winget reported success but Python 3.12 was not detected; falling back to direct download."
    }
    $exe = Install-Python312FromPythonOrg
    $v = Test-IsPython312 -Exe $exe -Pre @()
    if (-not $v) {
        throw "Installed Python at $exe is not reporting version 3.12; aborting."
    }
    return @{ Exe = $exe; Pre = @(); Version = $v }
}

function Resolve-Python312 {
    param(
        [string]$Preferred,
        [switch]$NoAutoInstall
    )

    if ($Preferred) {
        if (-not (Get-Command $Preferred -ErrorAction SilentlyContinue)) {
            throw "Python interpreter '$Preferred' was not found on PATH."
        }
        $v = Test-IsPython312 -Exe $Preferred -Pre @()
        if (-not $v) {
            throw "Python interpreter '$Preferred' is not 3.12 (found '$(& $Preferred --version)')."
        }
        Write-Host ">> Using $Preferred ($v)"
        return @{ Exe = $Preferred; Pre = @() }
    }

    $found = Find-Python312Launcher
    if ($found) {
        Write-Host ">> Using $($found.Exe) $($found.Pre -join ' ') ($($found.Version))"
        return @{ Exe = $found.Exe; Pre = $found.Pre }
    }

    if ($NoAutoInstall) {
        throw @"
Python 3.12 was not found on PATH and -NoAutoInstallPython was supplied.

APK Wooper's build requires Python 3.12 specifically (some optional
dependencies, notably APKiD's yara-python-dex, do not yet have wheels for
3.13 / 3.14).

Install it from https://www.python.org/downloads/release/python-3127/ or run:

    winget install -e --id Python.Python.3.12

Then re-run this script, or pass -Python "C:\path\to\python3.12.exe".
"@
    }

    Write-Host ">> Python 3.12 not detected; bootstrapping it now (no admin required)."
    $installed = Install-Python312
    Write-Host ">> Using $($installed.Exe) ($($installed.Version))"
    return @{ Exe = $installed.Exe; Pre = $installed.Pre }
}

function Invoke-Py {
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs
    )
    & $Exe @CmdArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed (exit $LASTEXITCODE): $Exe $($CmdArgs -join ' ')"
    }
}

function Invoke-PySafe {
    # Same as Invoke-Py but only warns on failure (used for optional steps).
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [string]$WarnPrefix = "WARNING"
    )
    & $Exe @CmdArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "${WarnPrefix}: command failed (exit $LASTEXITCODE): $Exe $($CmdArgs -join ' ')"
        return $false
    }
    return $true
}

# -------- 1. Find Python 3.12 (downloading it if missing) --------
$launcher = Resolve-Python312 -Preferred $Python -NoAutoInstall:$NoAutoInstallPython

# -------- 2. Create .apkwooper venv --------
if (-not (Test-Path $VenvPy)) {
    Write-Host ">> Creating virtual environment at $VenvDir"
    Invoke-Py -Exe $launcher.Exe -CmdArgs ($launcher.Pre + @("-m", "venv", $VenvDir))
} else {
    Write-Host ">> Reusing virtual environment at $VenvDir"
}

# Double-check the venv itself is 3.12 (catches the case where the user
# pointed an existing .apkwooper venv at a different interpreter).
$venvVersion = Test-IsPython312 -Exe $VenvPy -Pre @()
if (-not $venvVersion) {
    throw "Existing venv at $VenvDir is not Python 3.12. Delete it and rerun build."
}

Write-Host ">> Upgrading pip / setuptools / wheel"
Invoke-Py -Exe $VenvPy -CmdArgs @("-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel")

# -------- 3. Initialize .env --------
Write-Host ">> Initializing .env"
$initArgs = @((Join-Path $Root "scripts\init_env.py"))
if ($Force) { $initArgs += "--force" }
Invoke-Py -Exe $VenvPy -CmdArgs $initArgs

# -------- 4. Install requirements --------
Write-Host ">> Installing requirements.txt"
Invoke-Py -Exe $VenvPy -CmdArgs @(
    "-m", "pip", "install", "-r", (Join-Path $Root "requirements.txt")
)

if ($WithOptional) {
    Write-Host ">> Installing requirements-optional.txt"
    $ok = Invoke-PySafe -Exe $VenvPy -CmdArgs @(
        "-m", "pip", "install", "-r", (Join-Path $Root "requirements-optional.txt")
    ) -WarnPrefix "optional requirements"
    if (-not $ok) {
        Write-Warning "Some optional packages did not install. You can retry from Settings -> Analysis engine in the dashboard."
    }
}

# -------- 5. Install declared built-in plugin pip_requires --------
Write-Host ">> Installing declared built-in plugin pip dependencies"
Invoke-PySafe -Exe $VenvPy -CmdArgs @(
    (Join-Path $Root "scripts\bootstrap_plugin_deps.py")
) -WarnPrefix "plugin deps" | Out-Null

# -------- 6. Tool bootstrap --------
if ($SkipTools) {
    Write-Host ">> Skipping tool bootstrap (--SkipTools)"
} else {
    Write-Host ">> Bootstrapping tools (driven by .env ENABLE_* flags)"
    $toolArgs = @((Join-Path $Root "scripts\bootstrap_all_tools.py"))
    if ($WithTools) { $toolArgs += "--force" }
    Invoke-PySafe -Exe $VenvPy -CmdArgs $toolArgs -WarnPrefix "tool bootstrap" | Out-Null
}

# -------- 7. Plugin bootstrap (plugins.json + optional MobSF) --------
if ($SkipPlugins) {
    Write-Host ">> Skipping plugin bootstrap (--SkipPlugins)"
} else {
    Write-Host ">> Bootstrapping plugins"
    $pluginArgs = @((Join-Path $Root "scripts\bootstrap_plugins.py"))
    if ($WithMobSF) { $pluginArgs += "--with-mobsf-setup" }
    Invoke-PySafe -Exe $VenvPy -CmdArgs $pluginArgs -WarnPrefix "plugin bootstrap" | Out-Null
}

# -------- 8. Generate run.bat --------
Write-Host ">> Writing run.bat"
Invoke-Py -Exe $VenvPy -CmdArgs @((Join-Path $Root "scripts\write_run_bat.py"))

Write-Host ""
Write-Host "Build complete."
Write-Host ""
Write-Host "Next steps:"
Write-Host "  .\run.bat"
Write-Host ""
Write-Host "Then open http://127.0.0.1:5000 and log in with the password printed above"
Write-Host "(also saved to .admin_password.txt -- delete it after you store the password)."
