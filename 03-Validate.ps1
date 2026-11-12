<#
.SYNOPSIS
  STEP 3 - Validate that PHP2Shell is fixed on this server (and no longer active in the running Apache).

.DESCRIPTION
  Re-runs step 1 (tagged 'validate'), then judges the result:
    PASS/FAIL  every live PHP install is at or above the fixed version
    PASS/FAIL  every PHP DLL loaded by the RUNNING Apache is at or above the fixed version
               (catches "files replaced but Apache never restarted" and "a second PHP copy is what really serves the site")
    WARN       old PHP copies left on disk, MariaDB exposed on all interfaces, interim settings still in place
    REVIEW     PHP files in uploads folders / bursts of 5xx POST requests (possible earlier compromise)
  Compares with the newest earlier 'detect' result for this host. Exit code 0 = fixed, 2 = still vulnerable.
  Writes <HOST>_verdict_<time>.txt next to the other results.

.PARAMETER Url  Optional site URLs to probe; prints status and the Server / X-Powered-By headers.
                Header output is informational only - it is not proof of the PHP version.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\03-Validate.ps1 -Url https://example.goa.gov.in
#>
[CmdletBinding()]
param(
    [string]$OutDir = 'C:\PHP2Shell\results',
    [string[]]$Url,
    [switch]$Fast
)

$ErrorActionPreference = 'Continue'
$detect = Join-Path $PSScriptRoot '01-Detect-PHP2Shell.ps1'
if (-not (Test-Path $detect)) { throw "01-Detect-PHP2Shell.ps1 must be in the same folder as this script ($PSScriptRoot)." }

# earlier detect result for the before/after comparison (taken BEFORE the new run writes its own files)
$hostName = $env:COMPUTERNAME
$before = Get-ChildItem -Path $OutDir -Filter ("{0}_detect_*.json" -f $hostName) -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

$jsonPath = & $detect -OutDir $OutDir -Tag 'validate' -Fast:$Fast | Select-Object -Last 1
if (-not $jsonPath -or -not (Test-Path $jsonPath)) { throw 'Detection did not produce a result file.' }
$r = Get-Content -Raw -Path $jsonPath | ConvertFrom-Json

$verdict = Join-Path $OutDir ('{0}_verdict_{1}.txt' -f $hostName, (Get-Date -Format 'yyyyMMdd_HHmmss'))
$fails = 0; $warns = 0; $reviews = 0
function Out2([string]$m) { Write-Host $m; Add-Content -Path $verdict -Value $m -Encoding UTF8 }
function Pass([string]$m)   { Out2 "[PASS]   $m" }
function Fail([string]$m)   { $script:fails++;   Out2 "[FAIL]   $m" }
function Warn([string]$m)   { $script:warns++;   Out2 "[WARN]   $m" }
function Review([string]$m) { $script:reviews++; Out2 "[REVIEW] $m" }

Out2 ''
Out2 ('#' * 72)
Out2 "PHP2Shell VALIDATION - $hostName - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Out2 ('#' * 72)

# --- before / after ---
if ($before) {
    $b = Get-Content -Raw -Path $before.FullName | ConvertFrom-Json
    Out2 "Compared with earlier scan: $($before.Name)"
    foreach ($i in @($b.Installs | Where-Object { -not $_.IsBackupCopy })) {
        $now = @($r.Installs | Where-Object { $_.PhpDir -ieq $i.PhpDir }) | Select-Object -First 1
        Out2 ("  {0}: {1} ({2})  ->  {3} ({4})" -f $i.PhpDir, $i.Version, $i.Status, $(if ($now) { $now.Version } else { 'folder gone' }), $(if ($now) { $now.Status } else { '-' }))
    }
} else { Out2 'No earlier detect result found for this host - no before/after comparison.' }
Out2 ''

# --- 1. installs on disk ---
$live = @($r.Installs | Where-Object { -not $_.IsBackupCopy })
if ($live.Count -eq 0) { Warn 'No PHP installation found on this server.' }
foreach ($i in $live) {
    if ($i.Status -eq 'FIXED') { Pass "PHP at $($i.PhpDir) is $($i.Version) (fixed at $($i.RequiredVersion) or newer)." }
    else { Fail "PHP at $($i.PhpDir) is $($i.Version): $($i.Status). Needs: $($i.RequiredVersion)." }
}

# --- 2. what the running Apache has loaded ---
$fixedMap = @{ '8.5' = '8.5.12'; '8.4' = '8.4.27'; '8.3' = '8.3.36'; '8.2' = '8.2.35' }
$procs = @($r.HttpdProcesses)
if ($procs.Count -eq 0) { Warn 'Apache (httpd.exe) is not running, so the live PHP could not be checked. Start Apache and re-run.' }
else {
    $checked = @{}
    foreach ($p in $procs) {
        foreach ($m in @($p.PhpModules)) {
            if ($m.File -notmatch '(?i)php\d*ts\.dll$') { continue }
            if ($checked.ContainsKey($m.File + $m.ProductVersion)) { continue }
            $checked[$m.File + $m.ProductVersion] = 1
            $v = $null; try { $v = [version](($m.ProductVersion -replace '[^\d\.].*$', '').Trim('.')) } catch {}
            $ok = $false
            if ($v) { $br = '{0}.{1}' -f $v.Major, $v.Minor; if ($fixedMap.ContainsKey($br) -and $v -ge [version]$fixedMap[$br]) { $ok = $true } }
            if ($ok) { Pass "Running Apache (pid $($p.Pid), started $($p.Start)) has loaded $($m.File) = PHP $($m.ProductVersion)." }
            else     { Fail "Running Apache (pid $($p.Pid)) has loaded $($m.File) = PHP $($m.ProductVersion), which is NOT fixed. Restart Apache, or a different PHP copy is serving the site." }
        }
    }
    if ($checked.Count -eq 0) {
        $cgi = @($r.CgiProcesses)
        if ($cgi.Count) { foreach ($c in $cgi) { Out2 "  FastCGI process $($c.Name) pid $($c.Pid): $($c.Path) version $($c.Version) - compare with the fixed table by hand" } }
        Warn 'Apache runs but no PHP module is loaded in it (FastCGI / php-cgi?). Confirm the php-cgi.exe path and version above.'
    }
}

# --- 3. leftovers and hardening ---
foreach ($i in @($r.Installs | Where-Object { $_.IsBackupCopy -and $_.Status -ne 'FIXED' })) {
    Warn "Old vulnerable PHP copy still on disk: $($i.PhpDir) ($($i.Version)). It is inert unless loaded, but archive or delete it once the sites are tested."
}
foreach ($i in $live) {
    if ($i.Status -eq 'FIXED' -and ($i.UploadProgress -match 'Off|0' -or -not $i.UploadProgress)) { Out2 "[INFO]   $($i.PhpDir): session.upload_progress is off (fine to keep; it is rarely needed)." }
    if ($i.Status -eq 'FIXED' -and $i.MemoryLimit -eq '-1') { Warn "$($i.PhpDir): memory_limit is -1 (emergency setting). Restore a finite limit such as 256M." }
}
if ($r.Indicators.Db3306Exposed) { Warn 'MariaDB/MySQL port 3306 listens on all interfaces. Bind it to 127.0.0.1 unless remote access is required.' }

# --- 4. compromise indicators ---
if ($r.Indicators.UploadsPhpCount -gt 0) { Review "$($r.Indicators.UploadsPhpCount) PHP file(s) inside \uploads\ folders (see the detect report). Normally there are none - inspect each one." }
if ($r.Indicators.Http5xxPostCount -gt 50) { Review "$($r.Indicators.Http5xxPostCount) POST requests ended in HTTP 5xx in the recent access log. Look at the top client IPs in the detect report." }
if ($r.Indicators.RecentPhpCount -gt 0) { Out2 "[INFO]   $($r.Indicators.RecentPhpCount) PHP files changed since the 'modified since' date; compare the newest ones with what you deployed or updated." }

# --- 5. optional HTTP probe ---
foreach ($u in @($Url)) {
    if (-not $u) { continue }
    try {
        $resp = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 20 -MaximumRedirection 3
        Out2 ("[INFO]   {0} -> HTTP {1}; Server: {2}; X-Powered-By: {3}" -f $u, $resp.StatusCode, $resp.Headers['Server'], $resp.Headers['X-Powered-By'])
    } catch { Warn "$u did not answer: $($_.Exception.Message)" }
}

# --- verdict ---
Out2 ''
Out2 ('-' * 72)
$result = if ($fails -gt 0) { 'STILL VULNERABLE' } elseif ($live.Count -eq 0) { 'NO PHP FOUND' } else { 'FIXED' }
Out2 "RESULT: $result   (fails: $fails, warnings: $warns, review items: $reviews)"
if ($result -eq 'FIXED' -and $reviews -gt 0) { Out2 'PHP is patched, but the REVIEW items mean you cannot yet say nobody got in. Work through section 5 of the response guide (check, rotate secrets, report).' }
if ($result -eq 'FIXED' -and $reviews -eq 0) { Out2 'Patched and no compromise indicators found by these checks. Remember: these checks reduce risk, they do not prove a clean system.' }
Out2 "Verdict file : $verdict"
Out2 "Full scan    : $jsonPath"
if ($fails -gt 0) { exit 2 } else { exit 0 }
