# Keep Windows awake (no sleep / modern standby, screen on) while a package runs in ANOTHER window, without
# restarting it. Shows the P5c progress every 5 minutes and stops by itself when a new package-finished line appears
# in runs\logs\packages_done.txt (or close this window).  The laptop lid must stay open and the charger connected.
# Run:  powershell -ExecutionPolicy Bypass -File "<project folder>\runs\keep_awake.ps1"
. "$PSScriptRoot\_common.ps1"
$host.UI.RawUI.WindowTitle = 'keep awake'
Enable-KeepAwake
Disable-QuickEdit

$done = Join-Path $LogDir 'packages_done.txt'
$n0 = if (Test-Path $done) { (Get-Content $done).Count } else { 0 }
$log = Join-Path $LogDir 'P5c_new_models.log'
while ($true) {
    $n = 0
    if (Test-Path $log) {
        $fs = [System.IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
        $sr = New-Object System.IO.StreamReader($fs, [Text.Encoding]::Unicode)
        $n = ([regex]::Matches($sr.ReadToEnd(), '(?m)^\[result\]')).Count
        $sr.Close()
    }
    Write-Host ("{0}  awake; P5c runs finished: {1} of 39" -f (Get-Date -Format 'HH:mm'), $n) -ForegroundColor Cyan
    if ((Test-Path $done) -and (Get-Content $done).Count -gt $n0) {
        Write-Host 'a package finished - keep-awake released' -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 300
}
