<#
.SYNOPSIS
  STEP 4 (run on your own machine) - Roll up all server results into one CSV for the tracker.

.DESCRIPTION
  Collect the C:\PHP2Shell\results folders from each server into one folder on your laptop (for example
  .\all-results\WEB01\*.json), then run this. It reads every *_detect_*.json and *_validate_*.json,
  keeps the NEWEST result per host and kind, and writes PHP2Shell_summary.csv.

.EXAMPLE
  .\04-Summarize-Results.ps1 -ResultsDir .\all-results
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ResultsDir,
    [string]$OutFile = '.\PHP2Shell_summary.csv'
)

$files = Get-ChildItem -Path $ResultsDir -Recurse -Filter '*.json' | Where-Object { $_.Name -match '_(detect|validate)_\d{8}_\d{6}\.json$' }
if (-not $files) { throw "No *_detect_*.json or *_validate_*.json files found under $ResultsDir" }

$rows = foreach ($f in $files) {
    $d = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json
    $runMods = @($d.HttpdProcesses | ForEach-Object { $_.PhpModules } | Where-Object { $_.File -match '(?i)php\d*ts\.dll$' } | ForEach-Object { $_.ProductVersion } | Sort-Object -Unique) -join ', '
    $installs = @($d.Installs | Where-Object { -not $_.IsBackupCopy })
    if ($installs.Count -eq 0) { $installs = @([pscustomobject]@{ PhpDir = '(none found)'; Version = ''; Status = 'NO_PHP_FOUND'; RequiredVersion = ''; UploadProgress = ''; MemoryLimit = '' }) }
    foreach ($i in $installs) {
        [pscustomobject]@{
            Host                = $d.Host
            Scan                = $d.Tag
            ScanTime            = $d.Timestamp
            PhpDir              = $i.PhpDir
            PhpVersion          = $i.Version
            Status              = $i.Status
            NeedsVersion        = $i.RequiredVersion
            RunningApachePhp    = $runMods
            UploadProgress      = $i.UploadProgress
            MemoryLimit         = $i.MemoryLimit
            Db3306Exposed       = $d.Indicators.Db3306Exposed
            PhpFilesInUploads   = $d.Indicators.UploadsPhpCount
            Post5xxInLog        = $d.Indicators.Http5xxPostCount
            WordPress           = (@($d.WordPress | ForEach-Object { "$($_.Path) [$($_.WordPress)]" }) -join '; ')
            SourceFile          = $f.Name
        }
    }
}
$latest = $rows | Sort-Object ScanTime -Descending | Group-Object Host, Scan, PhpDir | ForEach-Object { $_.Group | Select-Object -First 1 } | Sort-Object Status, Host
$latest | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
$latest | Format-Table Host, Scan, PhpDir, PhpVersion, Status, RunningApachePhp -AutoSize
Write-Host ''
Write-Host ("{0} row(s) written to {1}" -f @($latest).Count, (Resolve-Path $OutFile))
Write-Host ("Still needing action: {0}" -f @($latest | Where-Object { $_.Status -ne 'FIXED' -and $_.Status -ne 'NO_PHP_FOUND' }).Count)
