# Shared settings and helpers for the run packages (dot-source this file: . "$PSScriptRoot\_common.ps1").
# Windows PowerShell 5.1. Every step is resumable: finished runs are skipped by the Python scripts themselves,
# so a package can simply be started again after an error or a reboot.

$ErrorActionPreference = 'Continue'
Set-Location (Split-Path $PSScriptRoot -Parent)                  # project folder
$env:PYTHONIOENCODING = 'utf-8'
$global:py = 'C:\Users\lenovo\.conda\envs\MyProject\python.exe'
$global:LogDir = Join-Path $PSScriptRoot 'logs'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Keep Windows awake while a package runs (no idle sleep / modern standby; the screen stays on) and turn off the
# console's QuickEdit mode, so that a click into the window cannot freeze the run. Released when PowerShell exits.
Add-Type -Namespace RunPkg -Name Native -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);
[DllImport("kernel32.dll")] public static extern System.IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll")] public static extern bool GetConsoleMode(System.IntPtr h, out uint mode);
[DllImport("kernel32.dll")] public static extern bool SetConsoleMode(System.IntPtr h, uint mode);
'@ -ErrorAction SilentlyContinue

function Write-Wait([string]$Text) {            # waits are shown and also written to runs\logs\_waits.log
    Write-Host $Text -ForegroundColor Yellow
    Add-Content -Path (Join-Path $LogDir '_waits.log') -Value ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Text)
}

function Enable-KeepAwake {
    # ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED
    [void][RunPkg.Native]::SetThreadExecutionState([uint32]'0x80000003')
    Write-Host '[awake] sleep and standby are blocked while this package runs (the lid must stay open)' -ForegroundColor Green
}

function Disable-QuickEdit {
    $h = [RunPkg.Native]::GetStdHandle(-10); $m = 0
    if ([RunPkg.Native]::GetConsoleMode($h, [ref]$m)) {
        [void][RunPkg.Native]::SetConsoleMode($h, (($m -band (-bnot 0x40)) -bor 0x80))
        Write-Host '[console] QuickEdit is off: clicking into this window no longer pauses the run' -ForegroundColor Green
    }
}

function Get-FreeCommitGB {
    [math]::Round((Get-CimInstance Win32_OperatingSystem).FreeVirtualMemory / 1MB, 1)
}

# Wait until Windows can commit at least $MinGB more memory (MemoryError / 'bad allocation' otherwise).
function Wait-Memory([double]$MinGB = 4, [int]$MaxMinutes = 30) {
    $t0 = Get-Date
    while ((Get-FreeCommitGB) -lt $MinGB) {
        if (((Get-Date) - $t0).TotalMinutes -gt $MaxMinutes) {
            Write-Wait "[memory] still below $MinGB GB after $MaxMinutes min - continuing anyway"
            return
        }
        Write-Wait ("[memory] free commit {0} GB < {1} GB - close programs (Chrome, ChatGPT, ...); waiting 30 s" -f (Get-FreeCommitGB), $MinGB)
        Start-Sleep -Seconds 30
    }
}

# Run one Python step once, with its output shown and appended to runs\logs\<Name>.log
function Invoke-Step([string]$Name, [string[]]$Arguments, [double]$MinGB = 3) {
    Wait-Memory $MinGB
    $log = Join-Path $LogDir "$Name.log"
    Write-Host ("==== {0}  {1}  (free {2} GB)" -f (Get-Date -Format 'HH:mm:ss'), $Name, (Get-FreeCommitGB)) -ForegroundColor Cyan
    & $py @Arguments 2>&1 | Tee-Object -FilePath $log -Append
}

# Run a step repeatedly (one model fit per process, as '--max-fits 1'); extra repetitions only print "nothing to do".
function Invoke-Loop([string]$Name, [string[]]$Arguments, [int]$Times, [double]$MinGB = 4) {
    for ($i = 1; $i -le $Times; $i++) {
        Write-Host "---- $Name  repetition $i of $Times" -ForegroundColor DarkCyan
        Invoke-Step $Name $Arguments $MinGB
    }
}

function Write-PackageDone([string]$Package) {
    $msg = "{0}  package {1} finished" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Package
    Write-Host "#### $msg" -ForegroundColor Green
    Add-Content -Path (Join-Path $LogDir 'packages_done.txt') -Value $msg
}
