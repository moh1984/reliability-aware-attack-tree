# 08_csrf.ps1 — graded d for CSRF (CWE-352, logic mechanism).
param([string]$sess = $env:DVWA_SESS)

# --- resolve results dir relative to THIS script (works from any CWD) ---
$RES = Join-Path (Split-Path -Parent $PSScriptRoot) "results"
if (-not (Test-Path $RES)) { New-Item -ItemType Directory -Force -Path $RES | Out-Null }

$cookie="PHPSESSID=$sess; security=low"
$U="http://localhost:8081/vulnerabilities/csrf/"; $D="http://localhost:9081/vulnerabilities/csrf/"
$variants=1..10 | ForEach-Object { "?password_new=Csrf{0:D2}&password_conf=Csrf{0:D2}&Change=Change" -f $_ }
$rows=@()
foreach($q in $variants){
 $ru=curl.exe -s -w "HTTPSTATUS:%{http_code}" -b $cookie "$U$q"
 $cU=($ru|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 $hU=if($ru -match "Password Changed"){1}else{0}
 $rd=curl.exe -s -w "HTTPSTATUS:%{http_code}" -b $cookie "$D$q"
 $cD=($rd|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 $hD=if($rd -match "Password Changed"){1}else{0}
 $rows+=[pscustomobject]@{request=$q;undef_code=$cU;undef_hit=$hU;def_code=$cD;def_hit=$hD}}
$rows|Format-Table -AutoSize
$rows|Export-Csv -NoTypeInformation -Encoding UTF8 $RES\csrf_matrix.csv
$nU=($rows|?{$_.undef_hit -eq 1}).Count; $nD=($rows|?{$_.def_hit -eq 1}).Count
$d=if($nU-gt 0){[math]::Round($nD/$nU,3)}else{"N/A"}
Write-Host "d(CSRF) = $nD / $nU = $d" -ForegroundColor Green
