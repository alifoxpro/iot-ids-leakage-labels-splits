# Package P5b (about 5 h, GPU): selection-rule sensitivity for the deep models under the temporal split, where the
# validation set comes from a later period: exactly 30 epochs, final weights, no early stopping (seeds 17, 42;
# 12 fits). Points expe-07, disc-14.
# Run ALONE:  powershell -ExecutionPolicy Bypass -File "<project folder>\runs\P5b_deep_fixed.ps1"
. "$PSScriptRoot\_common.ps1"

Invoke-Step 'P5b_plan' @('experiments\deep_protocol_study.py', '--protocol', 'fixed', '--splits', 'temporal', '--plan') 1
Invoke-Loop 'P5b_fixed_temporal' @('experiments\deep_protocol_study.py', '--protocol', 'fixed', '--splits', 'temporal', '--max-fits', '1') 14 5
Write-PackageDone 'P5b_deep_fixed'
