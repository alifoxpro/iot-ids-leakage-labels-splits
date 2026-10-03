# Package P5c (about 12 h, GPU; run overnight): two new deep baselines under the paper's protocol and the four
# conditions, five seeds each: a tuned MLP (4 configurations tried on random/raw, chosen by validation macro-F1)
# and the 1-D CNN of Hossain (2025) re-implemented from its description. Point expe-07.
# Run ALONE:  powershell -ExecutionPolicy Bypass -File "<project folder>\runs\P5c_new_baselines.ps1"
. "$PSScriptRoot\_common.ps1"

Invoke-Loop 'P5c_mlp_tune' @('experiments\deep_protocol_study.py', '--models', 'MLP', '--tune', '--max-fits', '1') 5 5
Invoke-Loop 'P5c_new_models' @('experiments\deep_protocol_study.py', '--protocol', 'earlystop', '--models', 'MLP', 'CNN1D_Hossain', '--max-fits', '1') 42 5
Write-PackageDone 'P5c_new_baselines'
