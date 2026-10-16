# 05_xss_reflected.ps1 — graded d for reflected XSS (CWE-79, reflected mechanism).
param([string]$sess = $env:DVWA_SESS)

# --- resolve results dir relative to THIS script (works from any CWD) ---
$RES = Join-Path (Split-Path -Parent $PSScriptRoot) "results"
if (-not (Test-Path $RES)) { New-Item -ItemType Directory -Force -Path $RES | Out-Null }

$cookie="PHPSESSID=$sess; security=low"
$U="http://localhost:8081/vulnerabilities/xss_r/"; $D="http://localhost:9081/vulnerabilities/xss_r/"
$payloads=@("<script>alert(1)</script>","<script>alert('xss')</script>","<img src=x onerror=alert(1)>",
 "<svg onload=alert(1)>","<body onload=alert(1)>","<iframe src=javascript:alert(1)>","<a href=javascript:alert(1)>x</a>",
 "<input onfocus=alert(1) autofocus>","<select onfocus=alert(1) autofocus>","<marquee onstart=alert(1)>",
 "<details open ontoggle=alert(1)>","<script>alert(String.fromCharCode(88))</script>","<ScRiPt>alert(1)</ScRiPt>",
 "<img src=x onerror=confirm(1)>","javascript:alert(1)","<svg><script>alert(1)</script></svg>")
$rows=@()
foreach($p in $payloads){
 $qs="?name=$([uri]::EscapeDataString($p))"
 $ru=curl.exe -s -w "HTTPSTATUS:%{http_code}" -b $cookie "$U$qs"
 $cU=($ru|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 $hU=if($ru -match [regex]::Escape($p)){1}else{0}
 $rd=curl.exe -s -w "HTTPSTATUS:%{http_code}" -b $cookie "$D$qs"
 $cD=($rd|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 $hD=if($rd -match [regex]::Escape($p)){1}else{0}
 $rows+=[pscustomobject]@{payload=$p;undef_code=$cU;undef_hit=$hU;def_code=$cD;def_hit=$hD}}
$rows|Format-Table -AutoSize
$rows|Export-Csv -NoTypeInformation -Encoding UTF8 $RES\xss_reflected_matrix.csv
$nU=($rows|?{$_.undef_hit -eq 1}).Count; $nD=($rows|?{$_.def_hit -eq 1}).Count
$d=if($nU-gt 0){[math]::Round($nD/$nU,3)}else{"N/A"}
Write-Host "d(ReflectedXSS) = $nD / $nU = $d" -ForegroundColor Green
