# Package P6 (about 20-30 min, no GPU): summaries that combine all new runs (including P5c), the stored-prediction
# analyses (packet-weighted detection, per-cell and per-class intervals, Wilson intervals), then the figures, the
# manuscript build and the PDF (Word). Run after the other packages:
#   powershell -ExecutionPolicy Bypass -File "<project folder>\runs\P6_final.ps1"
. "$PSScriptRoot\_common.ps1"
Enable-KeepAwake
Disable-QuickEdit

Invoke-Step 'P6_tree_summary' @('experiments\tree_seeds_summary.py') 2
Invoke-Step 'P6_tree_summary_refit' @('experiments\tree_seeds_summary.py', '--prefer-refit') 2
Invoke-Step 'P6_deep_summary' @('experiments\deep_protocol_summary.py') 2
Invoke-Step 'P6_published_deep_summary' @('experiments\published_deep_control.py', '--summary') 1
Invoke-Step 'P6_train_only_summary' @('experiments\cleaning_train_only.py', '--summary') 1
Invoke-Step 'P6_train_only_bootstrap' @('experiments\train_only_bootstrap.py') 3
Invoke-Step 'P6_analyses2' @('experiments\revision_analyses2.py', '--force') 3

Invoke-Step 'P6_figures' @('paper_q1\make_ijies_figures.py') 2
$env:IJIES_CONTENT = 'ijies_content_v3'
Invoke-Step 'P6_build' @('paper_submission\build_ijies.py') 1
Write-Host ("==== {0}  P6_pdf" -f (Get-Date -Format 'HH:mm:ss')) -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path (Split-Path $PSScriptRoot -Parent) 'paper_submission\rev2\docx_to_pdf.ps1') 2>&1 |
    Tee-Object -FilePath (Join-Path $LogDir 'P6_pdf.log') -Append
Write-PackageDone 'P6_final'
