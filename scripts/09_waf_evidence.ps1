# 09_waf_evidence.ps1 — capture live WAF responses on the defended port (403 injection vs 200 logic).
param([string]$sess = $env:DVWA_SESS)

# --- resolve results dir relative to THIS script (works from any CWD) ---
$RES = Join-Path (Split-Path -Parent $PSScriptRoot) "results"
if (-not (Test-Path $RES)) { New-Item -ItemType Directory -Force -Path $RES | Out-Null }

$ck="PHPSESSID=$sess; security=low"
"=== WAF EVIDENCE on defended port 9081  (run $(Get-Date -Format 'yyyy-MM-dd HH:mm')) ===" | Out-File -Encoding UTF8 $RES\waf_evidence.txt
"" | Out-File -Append -Encoding UTF8 $RES\waf_evidence.txt
"--- SQLi (CWE-89) direct injection ---" | Out-File -Append -Encoding UTF8 $RES\waf_evidence.txt
$sqli=curl.exe -s -i -b $ck "http://localhost:9081/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit"
($sqli|Select-String "HTTP/"|Select-Object -First 1)|Out-File -Append -Encoding UTF8 $RES\waf_evidence.txt
"" | Out-File -Append -Encoding UTF8 $RES\waf_evidence.txt
"--- CSRF (CWE-352) logic request ---" | Out-File -Append -Encoding UTF8 $RES\waf_evidence.txt
$csrf=curl.exe -s -i -b $ck "http://localhost:9081/vulnerabilities/csrf/?password_new=Proof01&password_conf=Proof01&Change=Change"
($csrf|Select-String "HTTP/"|Select-Object -First 1)|Out-File -Append -Encoding UTF8 $RES\waf_evidence.txt
$(if($csrf -match "Password Changed"){"Password Changed: YES (WAF allowed)"}else{"Password Changed: NO"})|Out-File -Append -Encoding UTF8 $RES\waf_evidence.txt
Get-Content $RES\waf_evidence.txt
