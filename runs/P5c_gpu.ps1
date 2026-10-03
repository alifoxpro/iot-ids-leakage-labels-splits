# Package P5c on the GPU (about 12 h; run overnight, charger connected): the same runs as P5c_new_baselines.ps1
# (MLP tuning, then MLP and CNN1D_Hossain with five seeds under the paper's protocol), with GPU safeguards:
#   * before every training step: charger check (waits while on battery) and a GPU test (PyTorch + CUDA);
#   * a second window shows the GPU load live (nvidia-smi), and runs\logs\P5c_gpu_usage.csv records it every 30 s;
#   * the Python script itself refuses to start without CUDA (it never falls back to the CPU);
#   * Windows is kept awake (no sleep/standby, screen on) and QuickEdit is off, so the run cannot pause unnoticed.
# Finished runs are skipped, so the package can simply be started again after an interruption.
# Run ALONE:  powershell -ExecutionPolicy Bypass -File "<project folder>\runs\P5c_gpu.ps1"
. "$PSScriptRoot\_common.ps1"

$env:CUDA_VISIBLE_DEVICES = '0'                  # the NVIDIA GPU only
$smi = (Get-Command nvidia-smi -ErrorAction SilentlyContinue).Source

function Test-OnCharger {
    $b = Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $b) { return $true }           # no battery information: assume mains power
    return [bool]$b.PowerOnline
}

function Wait-Charger {
    while (-not (Test-OnCharger)) {
        Write-Wait '[power] the laptop is on BATTERY - connect the charger (the GPU can be switched off on battery); waiting 30 s'
        Start-Sleep -Seconds 30
    }
}

function Wait-Gpu {
    while ($true) {
        & $py "$PSScriptRoot\gpu_check.py" 2>&1 | Tee-Object -FilePath (Join-Path $LogDir 'P5c_gpu_check.log') -Append
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

# live GPU monitor window and a CSV record of the GPU load
$mon = $null
if ($smi) {
    Start-Process powershell -ArgumentList '-NoExit', '-Command', "`$host.UI.RawUI.WindowTitle = 'GPU monitor (P5c)'; & '$smi' -l 5"
    $mon = Start-Process -FilePath $smi -WindowStyle Hidden -PassThru -ArgumentList @(
        '--query-gpu=timestamp,utilization.gpu,memory.used,power.draw,temperature.gpu', '--format=csv', '-l', '30',
        '-f', ('"{0}"' -f (Join-Path $LogDir 'P5c_gpu_usage.csv')))
} else {
    Write-Host '[gpu] nvidia-smi not found - no GPU monitor window' -ForegroundColor Yellow
}

Enable-KeepAwake
Disable-QuickEdit
try {
    Wait-Charger
    Wait-Gpu
    Invoke-GpuLoop 'P5c_mlp_tune' @('experiments\deep_protocol_study.py', '--models', 'MLP', '--tune', '--device', 'auto', '--max-fits', '1') 5
    Invoke-GpuLoop 'P5c_new_models' @('experiments\deep_protocol_study.py', '--protocol', 'earlystop', '--models', 'MLP', 'CNN1D_Hossain', '--device', 'auto', '--max-fits', '1') 42
    Write-PackageDone 'P5c_new_baselines'
} finally {
    if ($mon -and -not $mon.HasExited) { Stop-Process -Id $mon.Id -ErrorAction SilentlyContinue }
}
