# Package P5a (about 13 h, GPU; run overnight): the three deep models of the paper with three more seeds
# (7, 123, 2024) under the paper's protocol, so every deep cell has five seeds; stored probabilities and
# inference times. First a 10-minute check that a paper run is reproduced exactly. Points expe-08, stat-06,
# disc-11, stat-09, expe-09, expe-17.
# Run ALONE:  powershell -ExecutionPolicy Bypass -File "<project folder>\runs\P5a_deep_seeds.ps1"
. "$PSScriptRoot\_common.ps1"

Invoke-Step 'P5a_plan' @('experiments\deep_protocol_study.py', '--plan') 1
Invoke-Step 'P5a_rerun_check' @('experiments\deep_protocol_study.py', '--models', 'ResNet1D', '--splits', 'temporal', '--cleaning', 'r1', '--seeds', '42', '--rerun-existing', '--max-fits', '1') 5
Invoke-Loop 'P5a_earlystop_seeds' @('experiments\deep_protocol_study.py', '--protocol', 'earlystop', '--max-fits', '1') 38 5
Write-PackageDone 'P5a_deep_seeds'
