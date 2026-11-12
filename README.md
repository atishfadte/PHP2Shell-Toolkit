# PHP2Shell toolkit for Windows (XAMPP/WAMP) servers

Covers CVE-2026-109618 and CVE-2026-109619. Fixed PHP versions: **8.2.35, 8.3.36, 8.4.27, 8.5.12**. PHP 8.1 and older have no official fix.

## The flow, per server

```
 01-Detect  ->  .txt report + .json   (read-only)
     |
 02-Generate-Fixes (reads the .json)  ->  1-interim.ps1, 2-patch.ps1, 3-rollback.ps1, fix-plan.txt   (changes nothing)
     |
 you review, then run: 1-interim.ps1 (minutes)  ->  2-patch.ps1 (needs the PHP zip)
     |
 03-Validate  ->  verdict .txt   PASS / FAIL, exit code 0 = fixed, 2 = still vulnerable
     |
 04-Summarize-Results (on your laptop)  ->  PHP2Shell_summary.csv for the tracker
```

## Getting the files onto each server (IAP Desktop)

1. Keep this folder as `C:\PHP2Shell\` on each server. Copy and paste the folder through the RDP window (clipboard file copy), or put a zip in a Cloud Storage bucket and pull it on the server with `gsutil cp` if the Cloud SDK is installed there.
2. Open **PowerShell as Administrator** on the server. Administrator rights are required: reading which PHP DLL the running Apache has loaded needs them.
3. If scripts are blocked, run each one as `powershell -ExecutionPolicy Bypass -File .\<script>.ps1`.

## Step 1 - detect (read-only)

```powershell
cd C:\PHP2Shell
powershell -ExecutionPolicy Bypass -File .\01-Detect-PHP2Shell.ps1
```

* Searches every fixed disk for `php.exe`, `php-cgi.exe`, `httpd.exe` and the mod_php DLL. Add `-Fast` to search only XAMPP/WAMP/Program Files/inetpub folders.
* Writes `C:\PHP2Shell\results\<HOST>_detect_<time>.txt` (read it) and `.json` (the next step reads it).
* Reports: PHP version and status per install, the PHP DLL **actually loaded by the running Apache**, key php.ini values, Apache config lines, listening ports, WordPress sites, PHP files in uploads folders, PHP files modified since 1 Aug 2026, 5xx POST bursts in the access log, local admins and non-Microsoft scheduled tasks.
* The last lines say `OVERALL: ACTION_REQUIRED` or `FIXED`.

## Step 2 - generate fix scripts

```powershell
.\02-Generate-Fixes.ps1 -ResultFile C:\PHP2Shell\results\<HOST>_detect_<time>.json
```

Writes into `C:\PHP2Shell\fix\` (and prints) a plan plus, per vulnerable install:

| Script | What it does |
| --- | --- |
| `*_1-interim.ps1` | Backs up php.ini, sets `session.upload_progress.enabled=0`, `fatal_error_backtraces=0` (8.5 only), lowers `post_max_size` / `upload_max_filesize` only if they are higher than 32M / 16M, adds Apache `LimitRequestBody` (default 32 MB, change with `-LimitRequestBody`), tests the config and restarts Apache. |
| `*_2-patch.ps1` | Swaps in the fixed PHP from a zip you download. Refuses a zip whose compiler, 32/64-bit or thread-safety does not match the old build, backs up the Apache `conf`, keeps your php.ini, logs/tmp/sessions folders, tests `httpd -t` and `php -m`, starts Apache, and rolls back by itself on any error. A move to a newer branch needs `-ConfirmBranchUpgrade`. |
| `*_3-rollback.ps1` | Manual undo: puts back the newest `php_old_*` folder and `conf_bak_*`. |
| `*_fix-plan.txt` | The exact zip name to download and the order to run things. |

Download the zip on a machine with internet and copy it to `C:\PHP2Shell\downloads\`. The expected file name pattern is `php-<version>-Win32-vs16-x64.zip` (thread-safe build) from windows.php.net. Check the exact name on the site; I could not verify it from here.

Review each generated script before running it. Run `1-interim` first if you cannot patch right away, then `2-patch`. Test every site afterwards.

## Step 3 - validate

```powershell
.\03-Validate.ps1 -Url https://your-site.goa.gov.in
```

It re-runs step 1 and fails if any live PHP is below the fixed version, **or if the running Apache still has an unfixed PHP loaded** (replaced files but Apache not restarted, or a second PHP copy serving the site). It also flags old PHP copies left on disk, an exposed MariaDB port, a leftover `memory_limit=-1`, PHP files in uploads folders and 5xx POST bursts. Output: `<HOST>_verdict_<time>.txt`, exit code 0 or 2.

## Step 4 - roll up (on your laptop)

Copy each server's `results` folder into one folder (for example `all-results\WEB01\`), then:

```powershell
.\04-Summarize-Results.ps1 -ResultsDir .\all-results
```

## Limits to know about

* **Not tested on a live server.** I could not run PowerShell where I built these. Run step 1 and 2 on one low-risk server first and read the generated scripts before using them on production.
* IIS with PHP via FastCGI is only flagged, not handled: check the PHP path in IIS Manager under Handler Mappings and run step 1, which lists the `php-cgi.exe` versions it finds.
* XAMPP's own installers may lag behind PHP releases, and a PHP-only swap is not an official XAMPP procedure. If the zip does not match your Apache build, move that site to a maintained server instead of forcing it.
* No tool proves a server is clean. A PASS means the vulnerable code is gone and common indicators were not found; if the REVIEW items fire, treat the server as possibly compromised and rotate its secrets.
* Branch upgrades (for example 7.4 or 8.1 to 8.3) can break WordPress plugins and custom code. Test on a copy.
