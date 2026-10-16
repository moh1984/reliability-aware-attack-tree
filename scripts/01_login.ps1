# 01_login.ps1 — authenticate to DVWA, set security=low, emit the session cookie.
$r = Invoke-WebRequest -Uri "http://localhost:8081/login.php" -SessionVariable s -UseBasicParsing
$token = ($r.InputFields | Where-Object {$_.name -eq "user_token"}).value
Invoke-WebRequest -Uri "http://localhost:8081/login.php" -Method POST -WebSession $s -UseBasicParsing `
  -Body @{username="admin";password="password";Login="Login";user_token=$token} | Out-Null
$sess = ($s.Cookies.GetCookies("http://localhost:8081") | Where-Object {$_.Name -eq "PHPSESSID"}).Value
curl.exe -s -b "PHPSESSID=$sess; security=low" "http://localhost:8081/security.php" -d "security=low&seclev_submit=Submit" -o NUL
$test = curl.exe -s -b "PHPSESSID=$sess; security=low" "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit"
if ($test -match "First name") { Write-Host "Session OK. PHPSESSID = $sess" -ForegroundColor Green }
else { Write-Host "Session NOT ready. Re-run DVWA setup." -ForegroundColor Red }
