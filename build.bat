@echo off
REM Tiny CMD wrapper that runs build.ps1 with a permissive execution policy.
REM Forwards all arguments through, e.g.:  build.bat -Force -WithTools
setlocal
set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%build.ps1" %*
exit /b %ERRORLEVEL%
