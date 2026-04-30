param([string]$Target = "C:\WinDivert")

$ErrorActionPreference = "Stop"

try {
    $tmp = @($env:RUNNER_TEMP, $env:TEMP) | Where-Object { $_ } | Select-Object -First 1
    $zip  = Join-Path $tmp "WinDivert.zip"
    $dest = Join-Path $tmp "WinDivertTmp"

    Invoke-WebRequest "https://github.com/basil00/Divert/releases/download/v2.2.0/WinDivert-2.2.0-A.zip" -OutFile $zip

    Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive $zip $dest -Force

    $root = (Get-ChildItem $dest -Directory | Select-Object -First 1).FullName
    if (-not $root) { throw "Extraction failed - WinDivert root not found." }

    Remove-Item $Target -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $Target -Force | Out-Null

    foreach ($d in "include", "x64", "x86") {
        $path = Join-Path $root $d
        if (Test-Path $path) { Copy-Item $path $Target -Recurse -Force }
    }

    if ($env:GITHUB_ENV)  { "WinDivert_ROOT=$Target" | Out-File $env:GITHUB_ENV  -Append -Encoding utf8 }
    if ($env:GITHUB_PATH) { Join-Path $Target "x64"   | Out-File $env:GITHUB_PATH -Append -Encoding utf8 }

    Write-Host "WinDivert installation completed."
    exit 0
}
catch {
    Write-Error "Failed to install WinDivert: $($_.Exception.Message)"
    exit 1
}
