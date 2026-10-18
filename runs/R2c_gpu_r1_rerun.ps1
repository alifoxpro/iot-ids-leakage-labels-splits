# Package R2c (about 7-11 h, GPU; round-2 review, Reviewer 2, point 3; run ALONE, charger connected):
# repeats the 12 R1 network runs of the shared tuning budget (ResNet1D, GRU, Transformer, MLP x seeds 42, 17, 7).
# In R2b their validation loss was NaN in every epoch (one validation flow overflowed half precision), so they
# stopped after 10 epochs without early stopping on a finite loss; they are kept in
# results_2026_03_03\q1_revision\shared_budget\superseded_fp16_overflow\ (README.txt there). The training loop now
# evaluates such a validation chunk again in single precision. Same predeclared grid, chosen configurations,
# data and seeds as R2b; nothing else is refitted. Then the summary is written again.
# Safeguards as in R2b: charger check and GPU test before every fit, live GPU monitor window, GPU load recorded in
# runs\logs\R2c_gpu_usage.csv, keep-awake, QuickEdit off. Finished runs are skipped: start again after an interruption.
# Run ALONE:  powershell -ExecutionPolicy Bypass -File runs\R2c_gpu_r1_rerun.ps1
. "$PSScriptRoot\_common.ps1"

$env:CUDA_VISIBLE_DEVICES = '0'
$smi = (Get-Command nvidia-smi -ErrorAction SilentlyContinue).Source

function Test-OnCharger {
    $b = Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $b) { return $true }
    return [bool]$b.PowerOnline
}

function Wait-Charger {
    while (-not (Test-OnCharger)) {
        Write-Wait '[power] the laptop is on BATTERY - connect the charger; waiting 30 s'
        Start-Sleep -Seconds 30
    }
}

function Wait-Gpu {
    while ($true) {
        & $py "$PSScriptRoot\gpu_check.py" 2>&1 | Tee-Object -FilePath (Join-Path $LogDir 'R2c_gpu_check.log') -Append
        if ($LASTEXITCODE -eq 0) { return }
        Write-Wait '[gpu] the GPU is not usable - check the charger and the NVIDIA driver; retrying in 60 s'
        Start-Sleep -Seconds 60
    }
}

function Invoke-GpuLoop([string]$Name, [string[]]$Arguments, [int]$Times, [double]$MinGB = 5) {
    for ($i = 1; $i -le $Times; $i++) {
        Write-Host "---- $Name  repetition $i of $Times" -ForegroundColor DarkCyan
        Wait-Charger
        Wait-Gpu
        Invoke-Step $Name $Arguments $MinGB
    }
}

$mon = $null
if ($smi) {
    Start-Process powershell -ArgumentList '-NoExit', '-Command', "`$host.UI.RawUI.WindowTitle = 'GPU monitor (R2c)'; & '$smi' -l 5"
    $mon = Start-Process -FilePath $smi -WindowStyle Hidden -PassThru -ArgumentList @(
        '--query-gpu=timestamp,utilization.gpu,memory.used,power.draw,temperature.gpu', '--format=csv', '-l', '30',
        '-f', ('"{0}"' -f (Join-Path $LogDir 'R2c_gpu_usage.csv')))
}

Enable-KeepAwake
Disable-QuickEdit
try {
    Invoke-Step 'R2c_plan' @('experiments\shared_budget_study.py', '--plan', '--stage', 'final', '--families', 'nets') 1
    Invoke-GpuLoop 'R2c_final_nets' @('experiments\shared_budget_study.py', '--stage', 'final', '--families', 'nets', '--max-fits', '1') 13
    Invoke-Step 'R2c_summary' @('experiments\shared_budget_study.py', '--summary') 1
    Write-PackageDone 'R2c_gpu_r1_rerun'
} finally {
    if ($mon -and -not $mon.HasExited) { Stop-Process -Id $mon.Id -ErrorAction SilentlyContinue }
}
