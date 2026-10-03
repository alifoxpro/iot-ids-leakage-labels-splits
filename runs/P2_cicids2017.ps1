# Package P2 (about 30-45 min): replication on a second dataset, CICIDS2017 (identifier columns, random vs
# chronological split, protocol-0 compression, external-endpoint share). Point narr-03.
# Run:  powershell -ExecutionPolicy Bypass -File "<project folder>\runs\P2_cicids2017.ps1"
. "$PSScriptRoot\_common.ps1"

Invoke-Step 'P2_cicids_build' @('experiments\cicids2017_replication.py', '--build-only') 4
Invoke-Loop 'P2_cicids_fits' @('experiments\cicids2017_replication.py', '--max-fits', '1') 10 3
Invoke-Step 'P2_cicids_summary' @('experiments\cicids2017_replication.py', '--summary') 1
Write-PackageDone 'P2_cicids2017'
