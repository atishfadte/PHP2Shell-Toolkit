<#
.SYNOPSIS
  STEP 1 - Detect PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure on a Windows server.

.DESCRIPTION
  Read-only. Finds every PHP and Apache on the machine, reads the version of the PHP that Apache
  really has loaded, records the settings that matter, and looks for common signs of compromise.
  Writes two files per run into -OutDir:
     <HOST>_detect_<time>.txt   human-readable report (keep it, attach it to the ticket)
     <HOST>_detect_<time>.json  machine-readable result used by 02-Generate-Fixes.ps1

  Run in an elevated PowerShell (Run as administrator). Admin rights are needed to read which
  PHP DLL the running Apache process has loaded.

.PARAMETER OutDir         Where result files go. Default C:\PHP2Shell\results
.PARAMETER ModifiedSince  PHP files modified after this date are listed as "recent". Default 2026-08-01
.PARAMETER Tag            Used in the file name. 03-Validate uses 'validate'.
.PARAMETER Fast           Search only common folders (XAMPP, WAMP, Program Files, inetpub) instead of every disk.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\01-Detect-PHP2Shell.ps1
#>
[CmdletBinding()]
param(
    [string]$OutDir = 'C:\PHP2Shell\results',
    [string]$ModifiedSince = '2026-08-01',
    [string]$Tag = 'detect',
    [switch]$Fast
)

$ErrorActionPreference = 'SilentlyContinue'
$null = New-Item -ItemType Directory -Force -Path $OutDir
$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$hostName = $env:COMPUTERNAME
$txt      = Join-Path $OutDir ('{0}_{1}_{2}.txt'  -f $hostName, $Tag, $stamp)
$json     = Join-Path $OutDir ('{0}_{1}_{2}.json' -f $hostName, $Tag, $stamp)

function Log     { param([string]$Message = '') Write-Host $Message; Add-Content -Path $txt -Value $Message -Encoding UTF8 }
function Section { param([string]$Title) Log ''; Log ('=' * 72); Log $Title; Log ('=' * 72) }
function LogObj  { param($Obj) if ($null -eq $Obj -or @($Obj).Count -eq 0) { Log '  (none)' } else { Log (($Obj | Format-List | Out-String -Width 220).TrimEnd()) } }

# ---- Fixed versions published by PHP on 2026-10-21 -------------------------------------------
$FixedVersions = @{ '8.5' = '8.5.12'; '8.4' = '8.4.27'; '8.3' = '8.3.36'; '8.2' = '8.2.35' }

function Get-PhpStatus {
    param([string]$Version)
    $res = @{ Status = 'UNKNOWN'; Required = ''; Branch = '' }
    if (-not $Version) { return $res }
    try { $v = [version](($Version -replace '[^\d\.].*$', '').Trim('.')) } catch { return $res }
    $branch = '{0}.{1}' -f $v.Major, $v.Minor
    $res.Branch = $branch
    if ($FixedVersions.ContainsKey($branch)) {
        $res.Required = $FixedVersions[$branch]
        if ($v -ge [version]$FixedVersions[$branch]) { $res.Status = 'FIXED' } else { $res.Status = 'VULNERABLE_FIX_AVAILABLE' }
    }
    elseif ($v -lt [version]'8.2') { $res.Status = 'VULNERABLE_NO_OFFICIAL_FIX'; $res.Required = 'upgrade to 8.2.35+ / 8.3.36+ (no release for this branch)' }
    else { $res.Status = 'REVIEW_NEWER_BRANCH'; $res.Required = 'check php.net advisory for this branch' }
    return $res
}

function Get-InfoValue { param($Lines, [string]$Name)
    $m = $Lines | Where-Object { $_ -like "$Name =>*" } | Select-Object -First 1
    if ($m) { return (($m -replace '^[^=]*=>\s*', '').Trim()) }
}
function Get-IniValue { param($Lines, [string]$Name)
    $m = $Lines | Where-Object { $_ -like "$Name =>*" } | Select-Object -First 1
    if ($m) { return ((($m -split '=>')[1]).Trim()) }
}

# ---- Header ------------------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$os      = (Get-CimInstance Win32_OperatingSystem).Caption
Section "PHP2Shell detection report - $hostName - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Log "OS            : $os"
Log "Run as admin  : $isAdmin"
Log "Search mode   : $(if ($Fast) { 'FAST (common folders)' } else { 'FULL (all fixed disks)' })"
if (-not $isAdmin) { Log 'WARNING: not elevated. Loaded-module checks will be incomplete. Re-run as administrator.' }

# ---- 1. Locate binaries -------------------------------------------------------------------------
Section '1. Locating PHP and Apache binaries'
if ($Fast) {
    $roots = @('C:\xampp', 'D:\xampp', 'E:\xampp', 'C:\wamp', 'C:\wamp64', 'D:\wamp64', 'C:\php', 'C:\Program Files', 'C:\Program Files (x86)', 'C:\inetpub') | Where-Object { Test-Path $_ }
} else {
    $roots = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { $_.DeviceID + '\' })
}
$skip  = '\\(Windows\\WinSxS|\$Recycle\.Bin|Windows\\Installer)\\'
$found = foreach ($r in $roots) {
    Get-ChildItem -Path $r -Recurse -Force -File -Include 'php.exe', 'php-cgi.exe', 'httpd.exe', 'php*apache2*.dll' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch $skip }
}
$phpExes   = @($found | Where-Object { $_.Name -ieq 'php.exe' })
$httpdExes = @($found | Where-Object { $_.Name -ieq 'httpd.exe' })
$phpDlls   = @($found | Where-Object { $_.Name -like 'php*apache2*.dll' })
$phpCgis   = @($found | Where-Object { $_.Name -ieq 'php-cgi.exe' })
Log "php.exe found      : $($phpExes.Count)"
Log "httpd.exe found    : $($httpdExes.Count)"
Log "mod_php DLLs found : $($phpDlls.Count)"
Log "php-cgi.exe found  : $($phpCgis.Count)"

# ---- 2. PHP installs ---------------------------------------------------------------------------
Section '2. PHP installations (version, build, settings)'
$installs = @(foreach ($e in $phpExes) {
    $dir  = $e.DirectoryName
    $info = @(& $e.FullName -i 2>&1 | ForEach-Object { "$_" })
    $ver  = Get-InfoValue $info 'PHP Version'
    $st   = Get-PhpStatus $ver
    [pscustomobject]@{
        PhpDir              = $dir
        PhpExe              = $e.FullName
        Version             = $ver
        Branch              = $st.Branch
        Status              = $st.Status
        RequiredVersion     = $st.Required
        IsBackupCopy        = [bool]($dir -match '(?i)php[_\-\. ]?(old|bak|backup|new|failed)|\\(old|backup|bak)\\')
        Architecture        = Get-InfoValue $info 'Architecture'
        ThreadSafety        = Get-InfoValue $info 'Thread Safety'
        Compiler            = Get-InfoValue $info 'Compiler'
        BuildSystem         = Get-InfoValue $info 'Build System'
        LoadedIni           = Get-InfoValue $info 'Loaded Configuration File'
        HasModPhpDll        = [bool]($phpDlls | Where-Object { $_.DirectoryName -ieq $dir })
        HasPhpCgi           = [bool]($phpCgis | Where-Object { $_.DirectoryName -ieq $dir })
        UploadProgress      = Get-IniValue $info 'session.upload_progress.enabled'
        FatalErrorBacktrace = Get-IniValue $info 'fatal_error_backtraces'
        MemoryLimit         = Get-IniValue $info 'memory_limit'
        PostMaxSize         = Get-IniValue $info 'post_max_size'
        UploadMaxFilesize   = Get-IniValue $info 'upload_max_filesize'
        ExposePhp           = Get-IniValue $info 'expose_php'
        DisplayErrors       = Get-IniValue $info 'display_errors'
        RunError            = if (-not $ver) { ($info | Select-Object -First 2) -join ' | ' } else { '' }
    }
})
foreach ($i in $installs) {
    Log ''
    Log ("PHP at {0}" -f $i.PhpDir)
    Log ("  version        : {0}   status: {1}   needs: {2}" -f $i.Version, $i.Status, $i.RequiredVersion)
    Log ("  build          : {0} / {1} / thread-safe={2}" -f $i.Compiler, $i.Architecture, $i.ThreadSafety)
    Log ("  php.ini        : {0}" -f $i.LoadedIni)
    Log ("  upload_progress: {0}   fatal_error_backtraces: {1}   memory_limit: {2}   post_max: {3}   upload_max: {4}" -f $i.UploadProgress, $i.FatalErrorBacktrace, $i.MemoryLimit, $i.PostMaxSize, $i.UploadMaxFilesize)
    Log ("  mod_php DLL    : {0}   php-cgi: {1}   looks like backup copy: {2}" -f $i.HasModPhpDll, $i.HasPhpCgi, $i.IsBackupCopy)
    if ($i.RunError) { Log ("  could not run php.exe: {0}" -f $i.RunError) }
}

# ---- 3. Apache ---------------------------------------------------------------------------------
Section '3. Apache installations, services and the PHP that is actually loaded'
$apaches = @(foreach ($h in $httpdExes) {
    $root  = Split-Path $h.DirectoryName -Parent
    $ver   = (& $h.FullName -v 2>&1 | ForEach-Object { "$_" } | Select-Object -First 1)
    $confDir = Join-Path $root 'conf'
    $confFiles = @(Get-ChildItem -Path $confDir -Recurse -Filter '*.conf' -ErrorAction SilentlyContinue)
    $dirLines = @($confFiles | Select-String -Pattern '^\s*(LoadModule\s+php\S*|LoadFile\s+\S*php\S*|PHPIniDir|LimitRequestBody|Include(Optional)?\s+\S*php2shell\S*)' |
        ForEach-Object { '{0}:{1}: {2}' -f $_.Path, $_.LineNumber, $_.Line.Trim() })
    $docRoots = @($confFiles | Select-String -Pattern '^\s*DocumentRoot\s+' | ForEach-Object {
        $m = [regex]::Match($_.Line, 'DocumentRoot\s+"?([^"\r\n]+?)"?\s*$')
        if ($m.Success) { ($m.Groups[1].Value -replace '/', '\').Trim() } } | Where-Object { $_ -and ($_ -notmatch '\$\{') } | Sort-Object -Unique)
    [pscustomobject]@{
        HttpdExe    = $h.FullName
        Root        = $root
        Version     = $ver
        PhpDirectives = $dirLines
        DocRoots    = $docRoots
    }
})
$services = @(Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'httpd|php-cgi|W3SVC|inetinfo' } |
    ForEach-Object { [pscustomobject]@{ Name = $_.Name; State = $_.State; StartMode = $_.StartMode; Path = $_.PathName } })
$iis = [bool](Get-Service -Name W3SVC -ErrorAction SilentlyContinue)

$procs = @(foreach ($p in (Get-Process -Name httpd -ErrorAction SilentlyContinue)) {
    $mods = @($p.Modules | Where-Object { $_.ModuleName -match '^php' } | ForEach-Object {
        [pscustomobject]@{
            File           = $_.FileName
            ProductVersion = $_.FileVersionInfo.ProductVersion
            LastWrite      = (Get-Item $_.FileName).LastWriteTime.ToString('s')
        } })
    [pscustomobject]@{ Pid = $p.Id; Path = $p.Path; Start = $p.StartTime.ToString('s'); PhpModules = $mods }
})
$cgiProcs = @(Get-Process -Name php-cgi, php -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{ Name = $_.ProcessName; Pid = $_.Id; Path = $_.Path; Version = (Get-Item $_.Path).VersionInfo.ProductVersion } })

foreach ($a in $apaches) {
    Log ''
    Log ("Apache at {0}  ({1})" -f $a.Root, $a.Version)
    foreach ($l in $a.PhpDirectives) { Log ("  {0}" -f $l) }
    Log ("  DocumentRoot(s): {0}" -f ($a.DocRoots -join '; '))
}
Log ''
Log 'Windows services related to web serving:'
LogObj $services
Log ("IIS (W3SVC) present: {0}  - if True, check IIS FastCGI handlers separately (see README)" -f $iis)
Log ''
Log 'RUNNING Apache workers and the PHP DLLs they have loaded (this is the ground truth):'
if ($procs.Count -eq 0) { Log '  Apache (httpd.exe) is not running right now.' }
else {
    $seen = @{}
    foreach ($p in $procs) { foreach ($m in $p.PhpModules) {
        $k = "$($m.File)|$($m.ProductVersion)"
        if (-not $seen.ContainsKey($k)) { $seen[$k] = 1
            $s = Get-PhpStatus $m.ProductVersion
            Log ("  pid {0} started {1}: {2} version {3} -> {4}" -f $p.Pid, $p.Start, $m.File, $m.ProductVersion, $s.Status) } } }
    if ($seen.Count -eq 0) { Log '  httpd is running but no PHP DLL is loaded (PHP may run via FastCGI/php-cgi).' }
}
if ($cgiProcs.Count) { Log ''; Log 'Running php / php-cgi processes:'; LogObj $cgiProcs }

# ---- 4. Network exposure -----------------------------------------------------------------------
Section '4. Listening ports of interest'
$listen = @(Get-NetTCPConnection -State Listen | ForEach-Object {
    [pscustomobject]@{ Address = $_.LocalAddress; Port = $_.LocalPort; Process = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }
} | Where-Object { $_.Port -in 21, 80, 443, 3306, 3389, 5985, 8080, 8443 } | Sort-Object Port)
LogObj $listen
$dbExposed = @($listen | Where-Object { $_.Port -eq 3306 -and $_.Address -in '0.0.0.0', '::' })
if ($dbExposed.Count) { Log 'WARNING: MariaDB/MySQL (3306) listens on all interfaces. Bind it to 127.0.0.1 unless remote access is required.' }

# ---- 5. Sites ----------------------------------------------------------------------------------
Section '5. Web roots and WordPress sites'
$docRoots = @($apaches | ForEach-Object { $_.DocRoots } | Where-Object { $_ } | Sort-Object -Unique | Where-Object { Test-Path $_ })
foreach ($a in $apaches) { $d = Join-Path (Split-Path $a.Root -Parent) 'htdocs'; if ((Test-Path $d) -and ($docRoots -notcontains $d)) { $docRoots += $d } }
$wp = @(foreach ($dr in $docRoots) {
    Get-ChildItem -Path $dr -Recurse -Depth 3 -Filter 'wp-config.php' -ErrorAction SilentlyContinue | ForEach-Object {
        $site = $_.DirectoryName
        $vf   = Join-Path $site 'wp-includes\version.php'
        $wv   = ''
        if (Test-Path $vf) { $m = [regex]::Match((Get-Content $vf -Raw), '\$wp_version\s*=\s*''([^'']+)'''); if ($m.Success) { $wv = $m.Groups[1].Value } }
        [pscustomobject]@{ Path = $site; WordPress = $wv }
    } })
Log 'Document roots:'; foreach ($d in $docRoots) { Log "  $d" }
Log 'WordPress installs:'; LogObj $wp

# ---- 6. Compromise indicators ------------------------------------------------------------------
Section "6. Indicators of compromise (PHP files modified since $ModifiedSince, PHP inside uploads, 5xx POST bursts)"
$since  = [datetime]$ModifiedSince
$allPhp = @(foreach ($dr in $docRoots) {
    Get-ChildItem -Path $dr -Recurse -Force -File -Include '*.php', '*.phtml', '*.phar' -ErrorAction SilentlyContinue |
        Select-Object FullName, LastWriteTime, Length })
$uploadsPhp = @($allPhp | Where-Object { $_.FullName -match '\\uploads\\' } | Select-Object -First 200)
$recent     = @($allPhp | Where-Object { $_.LastWriteTime -gt $since } | Sort-Object LastWriteTime -Descending)
Log ("PHP files found under web roots           : {0}" -f $allPhp.Count)
Log ("PHP files inside any \uploads\ folder      : {0}   (should normally be 0)" -f $uploadsPhp.Count)
LogObj ($uploadsPhp | Select-Object -First 25)
Log ("PHP files modified since {0}            : {1}   (newest 40 shown; expect plugin/theme updates)" -f $ModifiedSince, $recent.Count)
LogObj ($recent | Select-Object -First 40)

$errPosts = 0; $topIps = @()
foreach ($a in $apaches) {
    $log = Join-Path $a.Root 'logs\access.log'
    if (Test-Path $log) {
        $hits = @(Get-Content $log -Tail 200000 | Select-String -Pattern '^(\S+) \S+ \S+ \[[^\]]+\] "POST \S+ [^"]*" (5\d\d) ')
        $errPosts += $hits.Count
        $topIps += @($hits | ForEach-Object { $_.Matches[0].Groups[1].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 |
            ForEach-Object { [pscustomobject]@{ Ip = $_.Name; Count = $_.Count; Log = $log } })
    }
}
Log ("POST requests answered with HTTP 5xx in the last 200000 access-log lines: {0}" -f $errPosts)
LogObj $topIps

$localUsers = @(Get-LocalUser | Select-Object Name, Enabled, LastLogon)
$admins     = @(Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass)
$tasks      = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' } |
    ForEach-Object { [pscustomobject]@{ Task = $_.TaskPath + $_.TaskName; State = $_.State; Runs = (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; ') } })
Log ''; Log 'Local administrators:'; LogObj $admins
Log 'Local users:'; LogObj $localUsers
Log 'Scheduled tasks outside \Microsoft\ (look for ones nobody created):'; LogObj $tasks

# ---- 7. Verdict ---------------------------------------------------------------------------------
Section '7. SUMMARY'
$live = @($installs | Where-Object { -not $_.IsBackupCopy })
$bad  = @($live | Where-Object { $_.Status -ne 'FIXED' })
$runBad = @()
foreach ($p in $procs) { foreach ($m in $p.PhpModules) { if ($m.File -match '(?i)php\d*ts\.dll$') { if ((Get-PhpStatus $m.ProductVersion).Status -ne 'FIXED') { $runBad += $m } } } }
$overall = if ($live.Count -eq 0) { 'NO_PHP_FOUND' } elseif ($bad.Count -or $runBad.Count) { 'ACTION_REQUIRED' } else { 'FIXED' }
foreach ($i in $live) { Log ("{0,-45} PHP {1,-10} {2}" -f $i.PhpDir, $i.Version, $i.Status) }
Log ''
Log "OVERALL: $overall"
if ($overall -eq 'ACTION_REQUIRED') { Log 'Next: run 02-Generate-Fixes.ps1 with the .json file written next to this report.' }
if ($uploadsPhp.Count -gt 0 -or $errPosts -gt 50) { Log 'REVIEW: indicators above need a human look (PHP in uploads and/or many 5xx POSTs).' }
Log "Report : $txt"
Log "Data   : $json"

$result = [pscustomobject]@{
    Host = $hostName; Timestamp = (Get-Date).ToString('s'); IsAdmin = $isAdmin; OS = $os; Tag = $Tag
    Overall = $overall; Installs = $installs; Apache = $apaches; Services = $services; IIS = $iis
    HttpdProcesses = $procs; CgiProcesses = $cgiProcs; Listeners = $listen; DocRoots = $docRoots; WordPress = $wp
    Indicators = [pscustomobject]@{
        UploadsPhpCount = $uploadsPhp.Count; UploadsPhp = @($uploadsPhp | ForEach-Object { $_.FullName })
        RecentPhpCount = $recent.Count; RecentPhp = @($recent | Select-Object -First 100 | ForEach-Object { '{0} | {1}' -f $_.FullName, $_.LastWriteTime.ToString('s') })
        Http5xxPostCount = $errPosts; TopIps = $topIps
        LocalAdmins = $admins; LocalUsers = $localUsers; ScheduledTasks = $tasks; Db3306Exposed = [bool]$dbExposed.Count
    }
}
$result | ConvertTo-Json -Depth 8 | Set-Content -Path $json -Encoding UTF8
return $json
