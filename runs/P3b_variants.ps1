# Package P3b (about 3 h): cleaning variants of Table 4 over five split seeds and three temporal cuts (XGBoost,
# 56 fits), training-only cleaning with the random forest (14 fits), and block-bootstrap intervals for every
# training-only cell and variant difference. Points meth-09, nove-05.
# Run:  powershell -ExecutionPolicy Bypass -File "<project folder>\runs\P3b_variants.ps1"
. "$PSScriptRoot\_common.ps1"

Invoke-Step 'P3b_variant_selftest' @('experiments\variant_seeds.py', '--selftest') 1
Invoke-Step 'P3b_variant_check' @('experiments\variant_seeds.py', '--check-splits') 3
Invoke-Loop 'P3b_variant_seeds' @('experiments\variant_seeds.py', '--max-fits', '1') 58 4
Invoke-Step 'P3b_variant_summary' @('experiments\variant_seeds.py', '--summary') 1

Invoke-Loop 'P3b_train_only_rf' @('experiments\cleaning_train_only.py', '--models', 'RandomForest', '--max-fits', '1') 16 4
Invoke-Step 'P3b_train_only_summary' @('experiments\cleaning_train_only.py', '--summary') 1

Invoke-Step 'P3b_bootstrap_selftest' @('experiments\train_only_bootstrap.py', '--selftest') 1
Invoke-Step 'P3b_train_only_bootstrap' @('experiments\train_only_bootstrap.py') 3
Write-PackageDone 'P3b_variants'
