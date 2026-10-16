# 02_zap_scan.ps1 — ZAP baseline (DAST) against all four endpoints.
# Load .env. docker compose reads .env by itself, but the `docker run` below does
# not, so without this a digest pinned in .env would silently be ignored here while
# it applied to the compose services - the one place the environment could drift.
# An already-set environment variable wins, matching compose's precedence.
$envFile = Join-Path (Split-Path -Parent $PSScriptRoot) ".env"
if (Test-Path $envFile) {
  foreach ($line in Get-Content $envFile) {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$') {
      $k, $v = $Matches[1], $Matches[2]
      if (-not (Test-Path "env:$k")) { Set-Item -Path "env:$k" -Value $v }
    }
  }
}

$zapImage = if ($env:ZAP_IMAGE) { $env:ZAP_IMAGE } else { "ghcr.io/zaproxy/zaproxy:stable" }
Write-Host "ZAP image: $zapImage" -ForegroundColor DarkGray

# --- resolve results dir relative to THIS script (works from any CWD) ---
$RES = Join-Path (Split-Path -Parent $PSScriptRoot) "results"
if (-not (Test-Path $RES)) { New-Item -ItemType Directory -Force -Path $RES | Out-Null }

$RES = $RES
$targets = @{
  "dvwa_undefended"="http://localhost:8081"; "dvwa_defended"="http://localhost:9081"
  "juiceshop_undefended"="http://localhost:8082"; "juiceshop_defended"="http://localhost:9082"
}
foreach ($name in $targets.Keys) {
  Write-Host ">> ZAP scanning $name ..." -ForegroundColor Cyan
  docker run --rm --network host -v "${RES}:/zap/wrk/:rw" `
    $zapImage zap-baseline.py `
    -t $targets[$name] -J "zap_$name.json" -r "zap_$name.html"
}
Write-Host "ZAP done. (Non-zero exit = alerts found; expected.)" -ForegroundColor Green
