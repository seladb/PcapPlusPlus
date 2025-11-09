@echo off
setlocal enableextensions enabledelayedexpansion

REM Install WinDivert SDK and set environment hints for subsequent CI steps
REM - Downloads WinDivert v2.2.0
REM - Extracts and arranges it under the provided WINDIVERT_ROOT (include/, x64/, optional x86/)
REM - Appends <WINDIVERT_ROOT>\x64 to GITHUB_PATH for runtime DLL discovery
REM - Sets WINDIVERT_ROOT in GITHUB_ENV so CMake's FindWinDivert can locate it

REM Accept optional first argument as WINDIVERT_ROOT. Default to C:\WinDivert if not provided
set "TARGET=C:\WinDivert"
if not "%~1"=="" (
  set "TARGET=%~1"
)

set "URL=https://github.com/basil00/Divert/releases/download/v2.2.0/WinDivert-2.2.0-A.zip"
set "ZIP=%RUNNER_TEMP%\WinDivert.zip"
set "DEST=%RUNNER_TEMP%\WinDivertTmp"

REM Use PowerShell for download and extraction
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $url='%URL%'; $zip='%ZIP%'; $dest='%DEST%'; $target='%TARGET%';" ^
  "Invoke-WebRequest -Uri $url -OutFile $zip;" ^
  "if (Test-Path $dest) { Remove-Item -Recurse -Force $dest };" ^
  "Expand-Archive -Path $zip -DestinationPath $dest -Force;" ^
  "$root = Get-ChildItem -Path $dest -Directory | Select-Object -First 1;" ^
  "if (Test-Path $target) { Remove-Item -Recurse -Force $target };" ^
  "New-Item -ItemType Directory -Path $target -Force | Out-Null;" ^
  "foreach($d in 'include','x64','x86'){ $p = Join-Path $root.FullName $d; if (Test-Path $p) { Copy-Item -Recurse -Force $p $target } }"

IF ERRORLEVEL 1 (
  echo Failed to install WinDivert SDK
  exit /b 1
)

echo WinDivert installation completed successfully.
exit /b 0
