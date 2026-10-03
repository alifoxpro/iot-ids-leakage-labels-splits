# Package P3a (about 3 h): tree ensembles with five seeds, stored class probabilities (average precision),
# inference times, and the refit check of the paper runs. Points expe-08, expe-09, expe-17, disc-11, stat-09.
# Run:  powershell -ExecutionPolicy Bypass -File "<project folder>\runs\P3a_trees_seeds_proba.ps1"
. "$PSScriptRoot\_common.ps1"

Invoke-Step 'P3a_plan' @('experiments\tree_seeds_proba.py', '--plan') 1
# 28 core fits: XGBoost/LightGBM/RF refits at seed 42 + LightGBM/RF seeds 123 and 2024 (one fit per process)
Invoke-Loop 'P3a_tree_seeds' @('experiments\tree_seeds_proba.py', '--max-fits', '1') 30 4
# 16 more fits: probabilities and timing for the existing seeds 17 and 7 as well
Invoke-Loop 'P3a_tree_seeds_old' @('experiments\tree_seeds_proba.py', '--with-old-seeds', '--max-fits', '1') 18 4
Invoke-Step 'P3a_plan_after' @('experiments\tree_seeds_proba.py', '--plan', '--with-old-seeds') 1
Invoke-Step 'P3a_summary' @('experiments\tree_seeds_summary.py') 2
Write-PackageDone 'P3a_trees_seeds_proba'
