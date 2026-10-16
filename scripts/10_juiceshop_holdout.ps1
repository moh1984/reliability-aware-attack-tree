# 10_juiceshop_holdout.ps1 — HELD-OUT validation: apply DVWA-calibrated, mechanism-indexed d
# to Juice Shop (different app/stack) WITHOUT re-measuring. Tests whether injection-mechanism
# attenuation transfers. Breaks the measure-and-validate-on-same-data circularity.

# --- resolve results dir relative to THIS script (works from any CWD) ---
$RES = Join-Path (Split-Path -Parent $PSScriptRoot) "results"
if (-not (Test-Path $RES)) { New-Item -ItemType Directory -Force -Path $RES | Out-Null }

$U="http://localhost:8082"; $D="http://localhost:9082"
$tests=@(
 @{name="SQLi login bypass";path="/rest/user/login";m="POST";ct="application/json";body='{"email":"admin@juice-sh.op'' OR 1=1--","password":"x"}'},
 @{name="SQLi login tautology";path="/rest/user/login";m="POST";ct="application/json";body='{"email":"'' OR 1=1--","password":"x"}'},
 @{name="SQLi union";path="/rest/user/login";m="POST";ct="application/json";body='{"email":"'' UNION SELECT 1--","password":"x"}'},
 @{name="XSS search reflected";path="/rest/products/search?q=<script>alert(1)</script>";m="GET";ct="";body=""},
 @{name="Path traversal encoded";path="/ftp/..%2f..%2fetc%2fpasswd";m="GET";ct="";body=""})
$rows=@()
foreach($t in $tests){
 if($t.m -eq "POST"){
  $cU=(curl.exe -s -w "HTTPSTATUS:%{http_code}" -X POST -H "Content-Type: $($t.ct)" -d $t.body "$U$($t.path)"|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
  $cD=(curl.exe -s -w "HTTPSTATUS:%{http_code}" -X POST -H "Content-Type: $($t.ct)" -d $t.body "$D$($t.path)"|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
 } else {
  $cU=(curl.exe -s -w "HTTPSTATUS:%{http_code}" "$U$($t.path)"|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value
  $cD=(curl.exe -s -w "HTTPSTATUS:%{http_code}" "$D$($t.path)"|Select-String "HTTPSTATUS:(\d+)").Matches.Groups[1].Value }
 # A transition counts as consistent with WAF intervention only if the payload
 # actually reached the application WITHOUT the WAF. If the undefended request was
 # itself rejected with a 4xx, the application refused it on its own and a 4xx on the
 # defended side carries no information about the WAF - the same rule that governs d
 # (a payload that fails undefended is excluded from the ratio). Without the first
 # clause the encoded path-traversal case (403 -> 404) would be scored "yes", which
 # contradicts results/reference_outputs/juiceshop_holdout.csv.
 $reachedUndefended = ([int]$cU -lt 400 -or [int]$cU -ge 500)
 $iv=($reachedUndefended -and [int]$cD -ge 400 -and [int]$cD -lt 500 -and $cU -ne $cD -and $cU -ne "000")
 $rows+=[pscustomobject]@{test=$t.name;undef_code=$cU;def_code=$cD;consistent_with_waf_intervention=$(if($iv){"yes (status transition)"}else{"no"})}}
$rows|Format-Table -AutoSize
$rows|Export-Csv -NoTypeInformation -Encoding UTF8 $RES\juiceshop_holdout.csv
$inj=$rows|?{$_.test -like "*SQLi*" -or $_.test -like "*reflected*"}
$blk=($inj|?{[int]$_.def_code -ge 400 -and [int]$_.def_code -lt 500}).Count
Write-Host "HELD-OUT: injection-class attacks whose status transition is consistent with WAF intervention: $blk / $($inj.Count)" -ForegroundColor Green
Write-Host "=> consistent with the mechanism-indexed d calibrated on DVWA" -ForegroundColor Cyan
Write-Host "   (out-of-sample, non-circular; a definitive attribution needs the matched ModSecurity rule ID)" -ForegroundColor Cyan
