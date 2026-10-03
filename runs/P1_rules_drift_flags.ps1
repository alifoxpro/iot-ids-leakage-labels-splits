# Package P1 (about 2.5-3 h, no deep training): extended rule validation (floods, Mirai, Recon; audit of R1 flags;
# sample for the manual audit), drift calibration (null reference, time-blocked folds, equal-size Jaccard), and the
# export of the per-flow flags keyed by source CSV and row. Points meth-02, nove-03, stat-08, meth-00.
# Run:  powershell -ExecutionPolicy Bypass -File "<project folder>\runs\P1_rules_drift_flags.ps1"
. "$PSScriptRoot\_common.ps1"

# --- rule validation 2 (reads the raw CSVs capture by capture; about 15-30 min)
Invoke-Step 'P1_rules2_selftest' @('experiments\rule_validation2.py', '--self-test') 1
Invoke-Loop 'P1_rules2' @('experiments\rule_validation2.py', '--max-captures', '1') 17 3
Invoke-Step 'P1_rules2_merge' @('experiments\rule_validation2.py', '--merge') 1

# --- drift calibration, R1 data (one capture group per process), then all-rules data (about 1-2 h)
Invoke-Loop 'P1_drift_cal' @('experiments\drift_calibration.py', '--max-fits', '1') 18 3
Invoke-Step 'P1_drift_cal' @('experiments\drift_calibration.py') 3
Invoke-Step 'P1_drift_cal_all' @('experiments\drift_calibration.py', '--cleaning', 'all') 3
Invoke-Step 'P1_drift_cal_summary' @('experiments\drift_calibration.py', '--summary') 1
Invoke-Step 'P1_drift_cal_summary' @('experiments\drift_calibration.py', '--summary', '--cleaning', 'all') 1

# --- per-flow flags and split membership keyed by (csv, row) (reads all CSVs once; about 30-45 min, peak 2.5-4 GB)
Invoke-Step 'P1_export_flags' @('experiments\export_flags.py') 5
Write-PackageDone 'P1_rules_drift_flags'
