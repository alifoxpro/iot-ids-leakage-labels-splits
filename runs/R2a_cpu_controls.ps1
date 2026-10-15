# Package R2a (about 3-5 h; round-2 review): controls that need no deep-network training.
#   1. audit sampling design: stratum counts, inclusion probabilities, estimands (Reviewer 1, point 2; seconds)
#   2. R3 with the Benign reference frozen on the training flows (Reviewer 1, point 1):
#      XGBoost 20 fits (GPU, ~15 min incl. loading), random forest 20 fits (a few minutes each, one per process)
#   3. rolling-origin, reversed and middle-block evaluation (Reviewer 2, point 2):
#      XGBoost 14 fits, random forest 14 fits (one per process)
#   4. comparison family of Section 5.4, paired block bootstrap with automatic block length, leave one capture
#      group out (Reviewer 1, point 3; stored predictions only, about 1-3 h)
# Finished runs are skipped, so the package can simply be started again after an interruption.
# Run (alone, not together with R2b):  powershell -ExecutionPolicy Bypass -File runs\R2a_cpu_controls.ps1
. "$PSScriptRoot\_common.ps1"
Enable-KeepAwake
Disable-QuickEdit

Invoke-Step 'R2a_audit_design' @('experiments\audit_design.py') 1

Invoke-Step 'R2a_r3_xgb' @('experiments\r3_train_reference.py', '--models', 'XGBoost') 4
Invoke-Loop 'R2a_r3_rf' @('experiments\r3_train_reference.py', '--models', 'RandomForest', '--max-fits', '1') 22 5
Invoke-Step 'R2a_r3_summary' @('experiments\r3_train_reference.py', '--summary') 1

Invoke-Step 'R2a_rolling_xgb' @('experiments\rolling_origin.py', '--models', 'XGBoost') 4
Invoke-Loop 'R2a_rolling_rf' @('experiments\rolling_origin.py', '--models', 'RandomForest', '--max-fits', '1') 16 5
Invoke-Step 'R2a_rolling_summary' @('experiments\rolling_origin.py', '--summary') 1

Invoke-Step 'R2a_bootstrap_family' @('experiments\bootstrap_family.py') 3
Write-PackageDone 'R2a_cpu_controls'
