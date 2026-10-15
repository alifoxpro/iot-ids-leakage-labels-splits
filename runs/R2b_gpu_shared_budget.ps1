# Package R2b (about 1-2 days; round-2 review, Reviewer 2, point 3; run ALONE, charger connected):
# every model family gets the same predeclared budget of four configurations (results_2026_03_03\q1_revision\
# shared_budget\grid.json, committed to the public repository before this package is run), selected on a
# validation set drawn from the training period; networks early-stopped on it with at most 100 epochs;
# final runs with seeds 42, 17, 7 on the temporal split with raw and R1 labels; ranking stability.
#   tuning:  20 network fits (GPU), 12 tree fits (XGBoost on the GPU, LightGBM and random forest on the CPU)
#   final:   25 network fits, 11 tree fits (the raw seed-42 runs are the chosen tuning runs)
# Safeguards as in P5c_gpu.ps1: charger check and GPU test before every network fit, live GPU monitor window,
# GPU load recorded in runs\logs\R2b_gpu_usage.csv, keep-awake, QuickEdit off. The Python script stops without
# CUDA instead of training on the CPU. Finished runs are skipped: start the package again after an interruption.
# Run ALONE:  powershell -ExecutionPolicy Bypass -File runs\R2b_gpu_shared_budget.ps1
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
        & $py "$PSScriptRoot\gpu_check.py" 2>&1 | Tee-Object -FilePath (Join-Path $LogDir 'R2b_gpu_check.log') -Append
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
    Start-Process powershell -ArgumentList '-NoExit', '-Command', "`$host.UI.RawUI.WindowTitle = 'GPU monitor (R2b)'; & '$smi' -l 5"
    $mon = Start-Process -FilePath $smi -WindowStyle Hidden -PassThru -ArgumentList @(
        '--query-gpu=timestamp,utilization.gpu,memory.used,power.draw,temperature.gpu', '--format=csv', '-l', '30',
        '-f', ('"{0}"' -f (Join-Path $LogDir 'R2b_gpu_usage.csv')))
}

Enable-KeepAwake
Disable-QuickEdit
try {
    Invoke-Step 'R2b_plan' @('experiments\shared_budget_study.py', '--plan') 1
    Invoke-GpuLoop 'R2b_tune_nets' @('experiments\shared_budget_study.py', '--stage', 'tune', '--families', 'nets', '--max-fits', '1') 22
    Invoke-Loop 'R2b_tune_trees' @('experiments\shared_budget_study.py', '--stage', 'tune', '--families', 'trees', '--max-fits', '1') 14 6
    Invoke-GpuLoop 'R2b_final_nets' @('experiments\shared_budget_study.py', '--stage', 'final', '--families', 'nets', '--max-fits', '1') 27
    Invoke-Loop 'R2b_final_trees' @('experiments\shared_budget_study.py', '--stage', 'final', '--families', 'trees', '--max-fits', '1') 13 6
    Invoke-Step 'R2b_summary' @('experiments\shared_budget_study.py', '--summary') 1
    Write-PackageDone 'R2b_gpu_shared_budget'
} finally {
    if ($mon -and -not $mon.HasExited) { Stop-Process -Id $mon.Id -ErrorAction SilentlyContinue }
}
