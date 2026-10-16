# 00_setup.ps1 — bring up the testbed, verify liveness, capture tool versions.
# Run from the reliability-aware-attack-tree root in PowerShell (Docker Desktop must be running).

# --- resolve results dir relative to THIS script (works from any CWD) ---
$RES = Join-Path (Split-Path -Parent $PSScriptRoot) "results"
if (-not (Test-Path $RES)) { New-Item -ItemType Directory -Force -Path $RES | Out-Null }

docker version        | Tee-Object        -FilePath $RES\env_docker_version.txt
docker compose version | Tee-Object -Append -FilePath $RES\env_docker_version.txt
docker compose up -d
Start-Sleep -Seconds 60   # Juice Shop is slow to boot
docker compose ps
Write-Host "`n=== Endpoint liveness ===" -ForegroundColor Cyan
curl.exe -s -o NUL -w "DVWA  undefended 8081: %{http_code}`n" http://localhost:8081/
curl.exe -s -o NUL -w "DVWA  defended   9081: %{http_code}`n" http://localhost:9081/
curl.exe -s -o NUL -w "Juice undefended 8082: %{http_code}`n" http://localhost:8082/
curl.exe -s -o NUL -w "Juice defended   9082: %{http_code}`n" http://localhost:9082/
Write-Host "`nNext: browser -> http://localhost:8081/setup.php -> Create/Reset Database," -ForegroundColor Yellow
Write-Host "log in admin/password, DVWA Security = Low, then run 01_login.ps1" -ForegroundColor Yellow
