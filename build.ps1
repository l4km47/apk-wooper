# First-run bootstrap for apk-wooper (Windows PowerShell).
#
# - Creates .venv, installs requirements, generates .env with SECRET_KEY
#   and a hashed dashboard admin password.
#
# Flags:
#   -Force        Regenerate SECRET_KEY and admin password even if .env already has them.
#   -WithTools    Also run scripts/bootstrap_tools.ps1 to fetch JADX + Apktool now
#                 (otherwise the app downloads them on first start).
#   -NoVenv       Use the system Python directly instead of creating .venv.
#   -Python BIN   Use a specific Python launcher / interpreter.

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$WithTools,
    [switch]$NoVenv,
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Set-Location $Root

function Resolve-Launcher {
    param([string]$Preferred)

    if ($Preferred) {
        if (Get-Command $Preferred -ErrorAction SilentlyContinue) {
            return @{ Exe = $Preferred; Pre = @() }
        }
        throw "Python interpreter '$Preferred' was not found on PATH."
    }
    if (Get-Command py      -ErrorAction SilentlyContinue) { return @{ Exe = "py";      Pre = @("-3") } }
    if (Get-Command python  -ErrorAction SilentlyContinue) { return @{ Exe = "python";  Pre = @() } }
    if (Get-Command python3 -ErrorAction SilentlyContinue) { return @{ Exe = "python3"; Pre = @() } }
    throw "No Python launcher found. Install Python 3.10+ from https://www.python.org/ and retry."
}

# Run a python command; throws if the process exits non-zero.
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

$launcher = Resolve-Launcher -Preferred $Python

if (-not $NoVenv) {
    $venvDir = Join-Path $Root ".venv"
    $venvPy  = Join-Path $venvDir "Scripts\python.exe"
    if (-not (Test-Path $venvPy)) {
        Write-Host ">> Creating virtual environment at $venvDir"
        Invoke-Py -Exe $launcher.Exe -CmdArgs ($launcher.Pre + @("-m", "venv", $venvDir))
    }
    $pyExe = $venvPy
    $pyPre = @()
} else {
    $pyExe = $launcher.Exe
    $pyPre = $launcher.Pre
}

Write-Host ">> Upgrading pip"
Invoke-Py -Exe $pyExe -CmdArgs ($pyPre + @("-m", "pip", "install", "--upgrade", "pip", "--quiet"))

Write-Host ">> Installing requirements"
Invoke-Py -Exe $pyExe -CmdArgs ($pyPre + @("-m", "pip", "install", "-r", (Join-Path $Root "requirements.txt")))

Write-Host ">> Initializing .env (secrets + admin password)"
$initArgs = $pyPre + @((Join-Path $Root "scripts\init_env.py"))
if ($Force) { $initArgs += "--force" }
Invoke-Py -Exe $pyExe -CmdArgs $initArgs

if ($WithTools) {
    Write-Host ">> Bootstrapping JADX + Apktool"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "scripts\bootstrap_tools.ps1")
    if ($LASTEXITCODE -ne 0) { throw "bootstrap_tools.ps1 failed" }
}

Write-Host ""
Write-Host "Build complete."
Write-Host ""
Write-Host "Next steps:"
if (-not $NoVenv) {
    Write-Host "  .\.venv\Scripts\Activate.ps1"
}
Write-Host "  python -m apk_web"
Write-Host ""
Write-Host "Then open http://127.0.0.1:5000 and log in with the password printed above"
Write-Host "(also saved to .admin_password.txt -- delete it after you store the password)."
