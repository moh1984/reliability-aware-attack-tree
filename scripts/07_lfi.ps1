# 07_lfi.ps1 — graded d for file inclusion / path traversal (CWE-22).
param([string]$sess = $env:DVWA_SESS)

# --- resolve results dir relative to THIS script (works from any CWD) ---
$RES = Join-Path (Split-Path -Parent $PSScriptRoot) "results"
if (-not (Test-Path $RES)) { New-Item -ItemType Directory -Force -Path $RES | Out-Null }

$cookie="PHPSESSID=$sess; security=low"
$U="http://localhost:8081/vulnerabilities/fi/"; $D="http://localhost:9081/vulnerabilities/fi/"
$payloads=@("/etc/passwd","../../../../etc/passwd","....//....//....//etc/passwd","..%2f..%2f..%2f..%2fetc%2fpasswd",
 "/etc/passwd%00","../../../../../../etc/passwd","..\..\..\..\etc\passwd","%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
 "php://filter/convert.base64-encode/resource=/etc/passwd","file:///etc/passwd")
$rows=@()
foreach($p in $payloads){
 $qs="?page=$([uri]::EscapeDataString($p))"
 $ru=curl.exe -s -w "HTTPSTATUS:%{http_code}" -b $cookie "$U$qs"
 $cU=($ru|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 $hU=if($ru -match "root:.*:0:0:|daemon:|/bin/bash|www-data:"){1}else{0}
 $rd=curl.exe -s -w "HTTPSTATUS:%{http_code}" -b $cookie "$D$qs"
 $cD=($rd|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 $hD=if($rd -match "root:.*:0:0:|daemon:|/bin/bash|www-data:"){1}else{0}
 $rows+=[pscustomobject]@{payload=$p;undef_code=$cU;undef_hit=$hU;def_code=$cD;def_hit=$hD}}
$rows|Format-Table -AutoSize
$rows|Export-Csv -NoTypeInformation -Encoding UTF8 $RES\lfi_matrix.csv
$nU=($rows|?{$_.undef_hit -eq 1}).Count; $nD=($rows|?{$_.def_hit -eq 1}).Count
$d=if($nU-gt 0){[math]::Round($nD/$nU,3)}else{"N/A"}
Write-Host "d(LFI) = $nD / $nU = $d" -ForegroundColor Green
