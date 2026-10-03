# Package P4 (about 1.5 h, GPU): the 1-D CNN of Hossain (2025), re-implemented from its description, in the
# approximated published setting: flow features alone (F0), + timestamp (FT), + all seven identifiers (FA);
# no class weights (published setting) and balanced weights; model seeds 42, 17 and 7; two input-layout checks.
# Points narr-00, expe-07. Needs results_2026_03_03\q1_revision\published_control\data.parquet (built earlier).
# Run ALONE (not together with another package):
#   powershell -ExecutionPolicy Bypass -File "<project folder>\runs\P4_published_deep.ps1"
. "$PSScriptRoot\_common.ps1"

Invoke-Step 'P4_plan' @('experiments\published_deep_control.py', '--plan') 1
Invoke-Loop 'P4_cnn_F0_FT' @('experiments\published_deep_control.py', '--max-fits', '1') 3 5
Invoke-Loop 'P4_cnn_FA' @('experiments\published_deep_control.py', '--sets', 'FA', '--max-fits', '1') 2 5
Invoke-Loop 'P4_cnn_balanced' @('experiments\published_deep_control.py', '--weightings', 'balanced', '--max-fits', '1') 3 5
Invoke-Loop 'P4_cnn_seeds' @('experiments\published_deep_control.py', '--seeds', '17', '7', '--max-fits', '1') 5 5
Invoke-Loop 'P4_cnn_pad_none' @('experiments\published_deep_control.py', '--pad', 'none', '--max-fits', '1') 3 5
Invoke-Loop 'P4_cnn_ids_first' @('experiments\published_deep_control.py', '--order', 'ids-first', '--max-fits', '1') 2 5
Invoke-Step 'P4_summary' @('experiments\published_deep_control.py', '--summary') 1
Write-PackageDone 'P4_published_deep'
