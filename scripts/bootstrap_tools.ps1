# Downloads JADX and Apktool into tools/ (Windows PowerShell)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Tools = Join-Path $Root "tools"
$JadxRoot = Join-Path $Tools "jadx"

$JadxVersion = "1.5.5"
$JadxZipUrl = "https://github.com/skylot/jadx/releases/download/v$JadxVersion/jadx-$JadxVersion.zip"
$ApktoolVersion = "2.11.1"
$ApktoolJarUrl = "https://github.com/iBotPeaches/Apktool/releases/download/v$ApktoolVersion/apktool_$ApktoolVersion.jar"

New-Item -ItemType Directory -Force -Path $Tools | Out-Null

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("jadx-bootstrap-" + [Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    Write-Host "Downloading JADX $JadxVersion ..."
    $zipPath = Join-Path $tmp "jadx.zip"
    Invoke-WebRequest -Uri $JadxZipUrl -OutFile $zipPath -UseBasicParsing
    Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
    if (Test-Path (Join-Path $tmp "lib") -PathType Container) {
        $extractedRoot = $tmp
    } else {
        $extracted = Get-ChildItem -Path $tmp -Directory | Where-Object {
            Test-Path (Join-Path $_.FullName "lib") -PathType Container
        } | Select-Object -First 1
        if (-not $extracted) {
            throw "Could not find JADX root (folder with lib/) after unzip"
        }
        $extractedRoot = $extracted.FullName
    }
    New-Item -ItemType Directory -Force -Path $JadxRoot | Out-Null
    Copy-Item -Path (Join-Path $extractedRoot "*") -Destination $JadxRoot -Recurse -Force
    Write-Host "JADX installed under $JadxRoot"

    Write-Host "Downloading Apktool $ApktoolVersion ..."
    $jarOut = Join-Path $Tools "apktool.jar"
    Invoke-WebRequest -Uri $ApktoolJarUrl -OutFile $jarOut -UseBasicParsing
    Write-Host "Apktool installed: $jarOut"
}
finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tmp
}

Write-Host "Done."
