# Package P0: regenerate all figures, then build the IJIES manuscript (about 2 minutes, no training).
# Run from any folder:   powershell -ExecutionPolicy Bypass -File "<project folder>\runs\P0_figures_build.ps1"
. "$PSScriptRoot\_common.ps1"

Invoke-Step 'P0_figures' @('paper_q1\make_ijies_figures.py') 2
$env:IJIES_CONTENT = 'ijies_content_v3'
Invoke-Step 'P0_build' @('paper_submission\build_ijies.py') 1
Write-PackageDone 'P0_figures_build'
