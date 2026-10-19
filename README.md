# Identifier Leakage, Folder Labels and Random Splits Distort the Evaluation of IoT Intrusion Detection: Evidence from CIC IoT-DIAD 2024

Code and result files of the paper

> **Identifier Leakage, Folder Labels and Random Splits Distort the Evaluation of IoT Intrusion Detection: Evidence
> from CIC IoT-DIAD 2024**
> A. H. Fadel, University of Diyala. Under review at the *International Journal of Intelligent Engineering and
> Systems* (IJIES), 2026.

The paper examines three properties of the evaluation protocol of CIC IoT-DIAD 2024: identifier columns (addresses,
ports, timestamp) among the features, labels taken from the folder of each capture (so that background traffic
recorded during an attack is labelled as that attack), and random rather than temporal splits. Eight models are
compared under these conditions: XGBoost, LightGBM, a random forest, three deep networks of the author's earlier
benchmark code (ResNet1D, GRU, Transformer), an MLP and a re-implementation of the published 1-D CNN of Hossain
(2025).

## Contents

| Path | Content |
|---|---|
| `experiments/` | the scripts of every experiment of the paper (tables below) |
| `src/` | the three modules of the author's earlier benchmark code that the deep networks import (see [Deep networks](#deep-networks)) |
| `runs/` | the PowerShell run packages with the exact arguments of the revision runs |
| `results_2026_03_03/` | the result files (CSV, JSON, TXT, Markdown) of every run reported in the paper |
| `manifest/` | the manifest: every run with its sample, preprocessing, labels, split, configuration, seed, stored predictions and model (`runs.csv`), the analyses (`analyses.csv`), the figure sources (`figures.csv`) and every paragraph, caption and table of the paper with its numbers and their result files (`paper_map.csv`) |
| `figures/values/` | the source values of every figure (one JSON per figure: every plotted value, unrounded, with its runs, seeds and source files) |
| `tools/evaluate_predictions.py` | recomputes the reported metrics of every run from its stored predictions and checks them against its result file |
| `tools/build_manifest.py` | writes `manifest/` |
| `tools/make_release_assets.py` | packs the large result files (stored predictions, model weights) for the GitHub Release |
| `environment.yml`, `requirements-lock.txt` | the exact software environment of the runs (conda export and pinned pip versions) |
| `RELEASE_CHECKLIST.md` | how the release assets are made |

## Installation

Reference environment: Python 3.11.14, PyTorch 2.10.0 + CUDA 12.8, NVIDIA RTX 5070 Laptop GPU (8 GB), Windows 11.

```bash
conda create -n iot-ids-eval python=3.11.14
conda activate iot-ids-eval
pip install -r requirements.txt
```

The tree ensembles run on the CPU; the deep networks need a CUDA GPU for reasonable run times. The exact environment of
the runs is in `environment.yml` (conda: `conda env create -f environment.yml`) and `requirements-lock.txt` (every pip
package with its version); `requirements.txt` lists only the packages the experiments import.

## Datasets

The datasets are not included. Download them and place them under `data/`:

| Dataset | Source | Folder |
|---|---|---|
| CIC IoT-DIAD 2024 (flow-based CSV release) | https://www.unb.ca/cic/datasets/iot-diad-2024.html | `data/CIC IoT-DIAD 2024/` |
| CICIDS2017 (replication; generated labelled flows) | https://www.unb.ca/cic/datasets/ids-2017.html | `data/cic-ids-2017/labelled-flows/` |

CIC IoT-DIAD 2024 is used with its eight folder-level classes (Benign, BruteForce, DDOS, DOS, Mirai, Recon, Spoofing,
Web-Based); the labels are taken from the folder names (`Label = NeedManualLabel` in the CSV files). Keep the folder
layout of the download, `data/CIC IoT-DIAD 2024/<class>/[<sub-attack>/]<capture>.pcap_Flow.csv` (for example
`DDOS/DDOS ICMP FLOOD/...`, `Web-Based/Uploading Attack/...`): the class folder gives the label and the sub-attack folder
the capture group. `results_2026_03_03/q1_revision/export_flags/files.csv` lists every file that is read, with its path
and record count, to check the download.

## Where to find each part of the paper

| Part of the paper | Scripts | Result folder |
|---|---|---|
| Evidence of label noise, capture groups, protocol 0 (Section 3.1, Fig. 2) | `pilot_temporal_split.py`, `temporal_split_by_subattack.py`, `diagnose_icmp_confusion.py`, `inspect_attack_ips.py`, `protocol_packet_share.py` | `split_pilot/` |
| Background rules R1–R3 and cleaning variants (Sections 3.2 and 5.3) | `relabel_background.py`, `flagged_loader.py`, `rule_sensitivity.py`, `tree_protocol_study.py` | `split_pilot/`, `tree_protocol/` |
| Validation of the rules and the audit of 472 flows (Section 3.3, Table 2, Fig. 2) | `rule_validation.py`, `rule_validation2.py` | `q1_revision/rule_validation/`, `q1_revision/rule_validation2/` |
| Main factorial: four protocol conditions, eight models, seeds (Sections 4.2 and 5.2–5.4, Table 6, Fig. 5) | `extra_baselines.py`, `deep_split_noise_study.py`, `tree_seeds_proba.py`, `tree_seeds_summary.py`, `deep_protocol_study.py`, `deep_protocol_summary.py` | `extra_baselines/`, `deep_split/`, `q1_revision/tree_seeds/`, `q1_revision/deep_protocol/` |
| Identifier columns and the published setting (Sections 4.3 and 5.1, Fig. 4) | `identifier_leakage.py`, `published_protocol_control.py`, `published_deep_control.py` | `identifier_leakage_v2/`, `q1_revision/published_control/`, `q1_revision/published_deep/` |
| Further split designs: split seeds, cut points, day-disjoint split, held-out sub-attacks (Section 5.2, Table 5, Fig. 6) | `split_replication.py`, `day_disjoint_split.py`, `leave_one_subattack_out.py` | `q1_revision/split_replication/`, `q1_revision/day_disjoint/`, `q1_revision/leave_one_subattack_out/` |
| Training-only and symmetric cleaning (Section 5.3, Table 5) | `cleaning_train_only.py`, `train_only_bootstrap.py`, `variant_seeds.py`, `symmetric_r1.py` | `q1_revision/cleaning_train_only/`, `q1_revision/train_only_bootstrap/`, `q1_revision/variant_seeds/`, `q1_revision/symmetric_r1/` |
| Uncertainty, drift, packet- and window-level detection (Sections 4.4 and 5.5) | `bootstrap_ci.py`, `temporal_drift_analysis.py`, `drift_calibration.py`, `revision_analyses.py`, `revision_analyses2.py` | `tree_protocol/`, `split_pilot/`, `q1_revision/drift_calibration/`, `q1_revision/analyses/`, `q1_revision/analyses2/` |
| Replication on CICIDS2017 (Sections 4.3, 5.1 and 5.6) | `cicids2017_replication.py` | `q1_revision/cicids2017/` |
| Per-flow flags and split assignments (Data availability) | `export_flags.py` | `q1_revision/export_flags/` |

All scripts are in `experiments/`; all result folders are under `results_2026_03_03/`. The exact commands, options
and outputs of each script are in its docstring.

## Label-noise and split-design study

CIC IoT-DIAD 2024 labels every flow by the folder of its pcap, so background traffic recorded during an attack is
labelled as that attack. These scripts measure the effect and compare split designs (run in this order; the first
run caches a sample to parquet):

| Script | Purpose |
|---|---|
| `experiments/pilot_temporal_split.py` | random vs per-class temporal split, held-out Uploading attack (XGBoost) |
| `experiments/temporal_split_by_subattack.py` | temporal split inside each of the 16 capture groups |
| `experiments/diagnose_icmp_confusion.py` | confusion per sub-attack, cross-class duplicates |
| `experiments/inspect_attack_ips.py` | dominant IP pairs, protocols and overlap with Benign per capture |
| `experiments/relabel_background.py` | background rules R1 (external endpoint), R2 (service ports), R3 (IP pair seen in Benign) |
| `experiments/flagged_loader.py` | shared loader that caches every flow with its rule flags |
| `experiments/rule_sensitivity.py` | no cleaning and six cleaning variants × two splits |
| `experiments/temporal_drift_analysis.py` | drift between training and test periods of each capture group |
| `experiments/deep_split_noise_study.py` | ResNet1D / GRU / Transformer × {random, temporal} × {raw, R1} × seeds (resumable) |
| `experiments/extra_baselines.py` | XGBoost, LightGBM and random forest under the same four conditions |
| `experiments/tree_protocol_study.py` | tree ensembles with several seeds; training-set vs test-set cleaning (`--max-fits 1` keeps memory low) |
| `experiments/bootstrap_ci.py` | stratified bootstrap CIs and paired model comparisons (Holm) from the stored predictions |
| `experiments/identifier_leakage.py` | effect of identifier columns (ports, protocol, addresses, timestamp) on accuracy |
| `experiments/protocol_packet_share.py` | flow and packet share per protocol: ICMP/GRE floods are recorded as protocol 0 by CICFlowMeter |

Results are written to `results_2026_03_03/split_pilot/`, `deep_split/`, `extra_baselines/`, `tree_protocol/` and
`identifier_leakage_v2/` (`identifier_leakage/` holds the results of an earlier version of `identifier_leakage.py`,
described in its docstring, that the paper does not use). Per-class precision, recall and F1 of every run are in
`results_2026_03_03/q1_revision/deep_protocol/summary/pooled_per_class.csv` (deep networks) and
`results_2026_03_03/q1_revision/tree_seeds/summary_per_class.csv` (tree ensembles). The cleaning rules and splits are
deterministic (seed 42). Test predictions (`*.npz`) are too large for git; they are attached to release v2.0 (see
[Release assets](#release-assets-stored-predictions-and-models)).

The scripts take the feature list and class order (through `pilot_temporal_split.py`) from
`results_2026_03_03/multiclass/stage1_cache/metadata.json` when it exists (it is not versioned), and otherwise from
the versioned copy `results_2026_03_03/multiclass/stage1_artifacts/CIC_IoT_DIAD_2024_metadata.json` (identical
`feature_columns` and `label_mapping`), so they run from a fresh clone once the dataset is in `data/`.

## Revision experiments

Scripts added for the revision of the paper. All of them use the flagged sample, features, cleaning (`kept_rows`),
partitions (`splits`) and model settings (`extra_baselines.make`) of the study above, unless the table says otherwise.
Every script is resumable (a run whose JSON exists is skipped), and the ones that train models accept `--max-fits N`,
so memory-heavy fits can run one per process. Results are written to `results_2026_03_03/q1_revision/<folder>/`.

| Script | Purpose | Folder |
|---|---|---|
| `experiments/split_replication.py` | random split with five split seeds and temporal cut at 60/70/80 %, XGBoost and random forest; class-weight ablation (none, square root, balanced) | `split_replication/` |
| `experiments/cleaning_train_only.py` | cleaning variants applied to the training rows only, all scored on the same test rows | `cleaning_train_only/` |
| `experiments/train_only_bootstrap.py` | i.i.d. and block-bootstrap intervals, and paired differences to "none", for the training-only cleaning runs (stored predictions only) | `train_only_bootstrap/` |
| `experiments/variant_seeds.py` | every cleaning variant of `rule_sensitivity.py` repeated over the partitions of `split_replication.py` | `variant_seeds/` |
| `experiments/symmetric_r1.py` | R1 applied to every class, or R1 flows relabelled Benign, to remove the Benign-only external-endpoint asymmetry | `symmetric_r1/` |
| `experiments/day_disjoint_split.py` | train/test cut at a calendar-day boundary inside each capture group | `day_disjoint/` |
| `experiments/leave_one_subattack_out.py` | seen versus held-out sub-attack on the same test flows: time effect versus unseen-variant effect | `leave_one_subattack_out/` |
| `experiments/tree_seeds_proba.py` | tree ensembles with five seeds, stored probabilities (average precision) and measured inference time | `tree_seeds/runs/` |
| `experiments/tree_seeds_summary.py` | seed mean, SD and range per condition, per-class precision / recall / AP, training and inference time | `tree_seeds/` |
| `experiments/deep_protocol_study.py` | deep models with five seeds, early stopping versus a fixed epoch budget, stored probabilities and inference time; new baselines: tuned MLP and a re-implemented 1-D CNN (Hossain 2025) | `deep_protocol/` |
| `experiments/deep_protocol_summary.py` | tables of the deep protocol study (seed values, mean, range and n per cell; pooled with the seeds of `deep_split/`) | `deep_protocol/` |
| `experiments/published_protocol_control.py` | identifier necessity control in the published setting: published class set, no de-duplication, random 80/20 split, label-encoded identifiers (XGBoost) | `published_control/` |
| `experiments/published_deep_control.py` | the same control with a Hossain-style 1-D CNN on the same table, split and feature sets | `published_deep/` |
| `experiments/cicids2017_replication.py` | identifier columns, random versus temporal split, protocol-0 share and an R1 analogue on CICIDS2017 (labelled-flow CSVs in `data/cic-ids-2017/labelled-flows/`) | `cicids2017/` |
| `experiments/rule_validation.py` | signature-based partial validation of R1–R3 on the BruteForce, Web-Based and Spoofing captures (all raw flows) | `rule_validation/` |
| `experiments/rule_validation2.py` | the signature-based validation extended to every attack capture, an audit of the R1-flagged flows (external endpoints seen in Benign, spoofed sources, ARP / DNS spoofing checks) and a stratified sample of flagged and kept flows for an audit of the rules (labelled by language-model annotators only, in `rule_validation2/llm_audit/`) | `rule_validation2/` |
| `experiments/pcap_validation.py` | R1–R3 scored against the attacking device (MAC address) of every flow, taken from the packet-level release (pcap files, requested separately from the dataset providers); one capture per run. Not run for the paper, which states that the rules are not validated against packet-level labels | `pcap_validation/<capture>/` |
| `experiments/drift_calibration.py` | null reference for the drift measures: two adjacent equal-size blocks inside the training period, time-blocked folds, port Jaccard on equal-size samples | `drift_calibration/` |
| `experiments/revision_analyses.py` | analyses of stored predictions: attack-class macro-F1, predictions on R1-flagged flows, block bootstrap, paired tests, per-class precision / recall, drift–loss association, flag share by period | `analyses/` |
| `experiments/revision_analyses2.py` | analyses of stored predictions: detection per capture, packet-weighted and on the protocol-0 flood flows; seed mean ± SD and bootstrap CIs per table cell; Wilson intervals for the per-sub-attack recalls | `analyses2/` |
| `experiments/export_flags.py` | per-flow R1/R2/R3 flags and split membership keyed by (source CSV, row), checked row for row against the cached sample and against the stored test rows of the experiments | `export_flags/` |

Numbering in older result files: `cicids2017/summary.json` (key `temporal (Algorithm 2)`) and
`cicids2017/split_temporal_F0.json` / `split_temporal_F78.json` (`split_desc`) were written when the temporal split
within capture groups was Algorithm 2 of the manuscript; there, 'Algorithm 2' means that split (Section 3.4 of the
submitted manuscript). The result files are kept as written; the script now uses the new wording. Some result files
also record the absolute local paths of the machine on which they were written.

## Per-flow flags and split assignments

`results_2026_03_03/q1_revision/export_flags/flow_flags.csv.gz` has one line per flow of the experimental sample
(3,626,502 flows) with the columns `csv` (path under `data/CIC IoT-DIAD 2024/`), `row` (0-based record number in
that file, header excluded), `idx` (row position used by all experiments), `y`, `sub`, `r1_external`, `r2_service`,
`r3_benign_pair` and `split_random`, `split_temporal`, `split_random_r1`, `split_temporal_r1` (`train`, `val`,
`test`, or `excluded` for R1-flagged flows). The runs that clean the training and the test part separately use
`split_random` / `split_temporal` and drop the flagged rows afterwards. `export_flags/export_flags.json` holds the
verification, the counts per class and split, and the SHA-256 of the export.

Reading the flag file and selecting, for example, the R1-cleaned training flows of the temporal split:

```python
import pandas as pd
f = pd.read_csv('results_2026_03_03/q1_revision/export_flags/flow_flags.csv.gz',
                dtype={'csv': 'category', 'sub': 'category'})
train = f[f['split_temporal_r1'] == 'train']          # (csv, row) locate each flow in the public CSVs
```

`export_flags/files.csv` lists the 124 CSV files that are read (the 129 files of the release without the five
one-row DoS-TCP-Flood files) with their number of records, records after the DoS/DDoS thinning and flows in the
sample. The partitions of designs that re-draw the split on the rows a cleaning variant keeps
(`rule_sensitivity.py`, `variant_seeds.py`) or use other seeds and cut points (`split_replication.py`) are not in
the file; the scripts regenerate them deterministically.

## Audit of the rules

`results_2026_03_03/q1_revision/rule_validation2/audit_sample.csv` is the stratified sample of the audit of the rules
(Section 3.3 of the paper): 472 raw flows of the seven attack classes (for every class and each of R1, R2, R3 and
their union, 20 flows flagged and 20 not flagged by the rule; a flow can serve several strata), drawn from all flows
of the attack captures, not only from the sample, and keyed like the flag file (`file` = `csv` there, and `row`). It
holds the identifier columns, key features, rule flags and heuristic labels; its own decision columns
(`audit_decision`, `audit_evidence`) are left empty. `audit_template_blind.md` shows the same flows without the rule
flags and heuristic labels; `rule_validation2.py --score-audit <filled template>` turns a filled template into
per-rule precision with Wilson intervals.

The audit was carried out by language-model annotators only: two blind annotators, an adjudicator and a third
annotator on a 40-flow spot check, all separate sessions of one language model. **No human checked any label.** The
instructions, evidence briefs and batch files given to the annotators, their decisions, the adjudications, the final
decisions, the agreement statistics, the scores and a record of the model and the dates are in
`rule_validation2/llm_audit/` (see its `README.md`). The annotation workflow was interrupted while only the final
assembly was pending and was resumed, so batches 10-19 of annotators A and B were annotated a second time with the same
instructions; the released labels are those of the second pass, and the first pass is kept in
`rule_validation2/llm_audit/first_pass_20260930/` (11 of the 472 final decisions differ, all between unclear and
background). `rule_validation2/audit_author_review_50.md` and `.xlsx` are unused, empty templates for a planned check by
the author that was not carried out.

## Deep networks

`src/` holds three modules copied unchanged from the author's earlier benchmark code
(https://github.com/alifoxpro/xai-ids-benchmark, the repository of a separate study): `stage3_ml_models.py` (network
definitions and training loop; this paper uses its ResNet1D, GRU and Transformer), `config.py` (model settings and
paths) and `stage1_data_preparation.py`, which `stage3_ml_models.py` imports. The MLP and the re-implemented 1-D CNN
of Hossain (2025) are defined in `experiments/deep_protocol_study.py` (and the published-setting variant of the
1-D CNN in `experiments/published_deep_control.py`).

## Reproducing the paper

Run from the project folder in PowerShell, in this order (later steps read the outputs of earlier ones).
`rule_sensitivity.py` (step 2) is the first script that uses `flagged_loader.py`; it reads the CSVs and caches the
sample as `results_2026_03_03/split_pilot/flagged_data.parquet`, which every later step reads.

```powershell
$py = "python"                     # the Python of the environment from "Installation"

# 1  split pilot, capture groups, protocol-0 compression
& $py experiments\pilot_temporal_split.py
& $py experiments\temporal_split_by_subattack.py
& $py experiments\diagnose_icmp_confusion.py
& $py experiments\inspect_attack_ips.py
& $py experiments\protocol_packet_share.py

# 2  background rules, flagged sample, drift
& $py experiments\relabel_background.py
& $py experiments\rule_sensitivity.py
& $py experiments\temporal_drift_analysis.py
& $py experiments\temporal_drift_analysis.py --cleaning r1

# 3  protocol study: deep models, tree ensembles, uncertainty, identifier columns
& $py experiments\deep_split_noise_study.py
& $py experiments\extra_baselines.py
1..48 | ForEach-Object { & $py experiments\tree_protocol_study.py --max-fits 1 }
& $py experiments\bootstrap_ci.py
& $py experiments\identifier_leakage.py

# 4  revision: repeated partitions and cleaning of the training rows only
& $py experiments\split_replication.py --models XGBoost
1..16 | ForEach-Object { & $py experiments\split_replication.py --models RandomForest --max-fits 1 }
& $py experiments\split_replication.py --study weights
& $py experiments\split_replication.py --summary
& $py experiments\cleaning_train_only.py
1..14 | ForEach-Object { & $py experiments\cleaning_train_only.py --models RandomForest --max-fits 1 }
& $py experiments\cleaning_train_only.py --summary
& $py experiments\train_only_bootstrap.py
& $py experiments\variant_seeds.py --check-splits
1..7 | ForEach-Object { & $py experiments\variant_seeds.py --max-fits 8 }
& $py experiments\variant_seeds.py --summary

# 5  revision: label and split controls
& $py experiments\symmetric_r1.py --models XGBoost
1..4 | ForEach-Object { & $py experiments\symmetric_r1.py --models RandomForest --max-fits 1 }
& $py experiments\symmetric_r1.py --summary
1..4 | ForEach-Object { & $py experiments\day_disjoint_split.py --max-fits 1 }
& $py experiments\day_disjoint_split.py --summary
1..26 | ForEach-Object { & $py experiments\leave_one_subattack_out.py --max-fits 1 }
& $py experiments\leave_one_subattack_out.py --summary

# 6  revision: stored-prediction analyses, seeds, probabilities and timing
& $py experiments\revision_analyses.py          # its block-bootstrap table is read by tree_seeds_summary.py
1..28 | ForEach-Object { & $py experiments\tree_seeds_proba.py --max-fits 1 }
& $py experiments\tree_seeds_summary.py
1..36 | ForEach-Object { & $py experiments\deep_protocol_study.py --protocol earlystop --max-fits 1 }
1..24 | ForEach-Object { & $py experiments\deep_protocol_study.py --protocol fixed --max-fits 1 }
1..4 | ForEach-Object { & $py experiments\deep_protocol_study.py --models MLP --tune --max-fits 1 }
1..39 | ForEach-Object { & $py experiments\deep_protocol_study.py --protocol earlystop --models MLP CNN1D_Hossain --max-fits 1 }
1..16 | ForEach-Object { & $py experiments\deep_protocol_study.py --protocol fixed --models MLP CNN1D_Hossain --max-fits 1 }
& $py experiments\deep_protocol_summary.py

# 7  revision: identifier necessity in the published setting
& $py experiments\published_protocol_control.py --build-only
1..6 | ForEach-Object { & $py experiments\published_protocol_control.py --max-fits 1 }
& $py experiments\published_protocol_control.py --summary
1..2 | ForEach-Object { & $py experiments\published_deep_control.py --max-fits 1 }
& $py experiments\published_deep_control.py --summary

# 8  revision: rule validation, drift reference, second dataset
& $py experiments\rule_validation.py
& $py experiments\rule_validation2.py
1..16 | ForEach-Object { & $py experiments\drift_calibration.py --max-fits 1 }
& $py experiments\drift_calibration.py --summary
& $py experiments\cicids2017_replication.py --build-only
1..8 | ForEach-Object { & $py experiments\cicids2017_replication.py --max-fits 1 }
& $py experiments\cicids2017_replication.py --summary

# 9  revision: analyses of all stored results and the published flags
& $py experiments\revision_analyses2.py
& $py experiments\export_flags.py
```

### Second-round revision experiments

Added for the second review round (results in `results_2026_03_03/q1_revision/<folder>/`; the exact commands are in
each docstring and in the packages `runs/R2a_cpu_controls.ps1`, `runs/R2b_gpu_shared_budget.ps1` and
`runs/R2c_gpu_r1_rerun.ps1`):

| Script | Purpose | Folder |
|---|---|---|
| `experiments/r3_train_reference.py` | R3 with the reference of Benign IP pairs frozen on the Benign **training** flows of each split (no validation or test flow informs the rule), in the training-only cleaning design; refits of the published variants for comparison | `r3_train_reference/` |
| `experiments/rolling_origin.py` | forward, reversed and middle-block test periods and three rolling origins inside every capture group, against the random split: the direction of time and the position of the test block, separated from the advantage of a random split (contiguous-block difficulty and the memorisation of neighbouring flows together); single runs, seed 42 | `rolling_origin/` |
| `experiments/bootstrap_family.py` | the 40 comparisons behind the model ranking of Section 5.4 (Holm over the 40), paired block-bootstrap intervals of the principal differences for block lengths 1 to 20,000 flows and an automatic length (Politis and White) per capture group, and leave-one-capture-group-out values | `bootstrap_family/` |
| `experiments/audit_design.py` | sampling design of the 472-flow audit: stratum sizes, inclusion probabilities, de-duplication of the 1,120 stratum slots, estimands with unclear decisions excluded or counted either way | `rule_validation2/design/` |
| `experiments/shared_budget_study.py` | the same predeclared budget of four configurations for every model family (`shared_budget/grid.json`, committed before any run), validation set drawn from the training period, networks with up to 100 epochs, final runs with three seeds, ranking stability and convergence; network, XGBoost and LightGBM weights are stored (random forests: refit from configuration and seed). In a first pass, one validation flow overflowed half precision in the validation pass of the R1 runs of ResNet1D, GRU, the Transformer and the MLP, so their validation loss was not finite and they stopped after 10 epochs; such a chunk is now evaluated in single precision (`deep_protocol_study.train`), the 12 runs were repeated (`runs/R2c_gpu_r1_rerun.ps1`) and the superseded runs are kept in `shared_budget/superseded_fp16_overflow/` with a README | `shared_budget/` |

A loop runs one model fit per process, which keeps the peak memory at that of a single fit. A script whose runs are
all finished only reports this and exits, so a loop may be longer than needed. The random-forest fits need several
GB of RAM each. Optional sensitivity runs (for example `deep_protocol_study.py --fixed-lr val`,
`tree_seeds_proba.py --with-old-seeds`, `drift_calibration.py --cleaning all`, `published_deep_control.py --sets FA`)
are listed in the docstrings of the scripts.

## Run packages (`runs/`)

The revision experiments were run as Windows PowerShell 5.1 packages, each a short `.ps1` file that runs one group of
the steps above with the exact arguments used for the paper:

```powershell
powershell -ExecutionPolicy Bypass -File runs\P1_rules_drift_flags.ps1
```

Every package dot-sources `runs/_common.ps1`, which changes to the project folder, sets `$py` (the Python of the
conda environment, a local path to edit on another machine) and `PYTHONIOENCODING`, and defines four helpers:
`Invoke-Step` runs one Python step and appends its output to `runs/logs/<step>.log`; `Invoke-Loop` repeats a step so
that each process makes one model fit (`--max-fits 1`); `Wait-Memory` waits before each step until Windows can commit
enough memory; and `Write-PackageDone` appends a line to `runs/logs/packages_done.txt`. It also provides
`Enable-KeepAwake`, which blocks idle sleep and modern standby and keeps the screen on while the package runs (the
lid must stay open; released when PowerShell exits), `Disable-QuickEdit`, which turns off the console's QuickEdit mode
so that a click into the window cannot pause a run, and `Write-Wait`, which shows every wait (memory, charger, GPU)
and also logs it to `runs/logs/_waits.log`. The scripts skip finished runs, so a package can simply be started again
after an error or a reboot. The logs are not versioned (`*.log`).

| Package | Steps | Time (approx.) |
|---|---|---|
| `P0_figures_build.ps1` | figures and manuscript build (sources not in this repository while the paper is under review) | 2 min |
| `P1_rules_drift_flags.ps1` | `rule_validation2.py` (self-test, one capture per process, merge), `drift_calibration.py` (R1 and all-rules data, summaries), `export_flags.py` | 2.5–3 h |
| `P2_cicids2017.ps1` | `cicids2017_replication.py` (data build, fits, summary) | 30–45 min |
| `P3a_trees_seeds_proba.ps1` | `tree_seeds_proba.py` (refits at seed 42, LightGBM and random forest with seeds 123 and 2024, then probabilities and timing for seeds 17 and 7), `tree_seeds_summary.py` | 3 h |
| `P3b_variants.ps1` | `variant_seeds.py` (self-test, split check, fits, summary), `cleaning_train_only.py --models RandomForest`, `train_only_bootstrap.py` | 3 h |
| `P4_published_deep.ps1` | `published_deep_control.py`: re-implemented 1-D CNN of Hossain (2025) in the approximated published setting (feature sets F0, FT, FA; no and balanced class weights; seeds 42, 17, 7; two input-layout checks) | 1.5 h, GPU |
| `P5a_deep_seeds.ps1` | `deep_protocol_study.py`: re-run check of a paper run (ResNet1D, temporal, R1, seed 42), then ResNet1D, GRU and Transformer with seeds 7, 123 and 2024 under early stopping | 13 h, GPU |
| `P5b_deep_fixed.ps1` | `deep_protocol_study.py --protocol fixed --splits temporal`: exactly 30 epochs, final weights, seeds 17 and 42 | 5 h, GPU |
| `P5c_new_baselines.ps1` | `deep_protocol_study.py`: MLP tuning (four configurations), then MLP and the re-implemented 1-D CNN under the four conditions with five seeds | 12 h, GPU |
| `P5c_gpu.ps1` | the same runs as `P5c_new_baselines.ps1` (with `--device auto`; the script refuses to start without CUDA and never falls back to the CPU), with safeguards for an unattended overnight run: before every fit it waits while the laptop is on battery and runs `gpu_check.py`; a second window shows `nvidia-smi` live and `runs/logs/P5c_gpu_usage.csv` records the GPU load every 30 s | 12 h, GPU |
| `P6_final.ps1` | summaries of all runs (`tree_seeds_summary.py`, also with `--prefer-refit`, `deep_protocol_summary.py`, `published_deep_control.py --summary`, `cleaning_train_only.py --summary`, `train_only_bootstrap.py`, `revision_analyses2.py --force`), then figures, manuscript build and PDF export (sources not in this repository while the paper is under review) | 20–30 min |
| `R2a_cpu_controls.ps1` | second round: `r3_train_reference.py`, `rolling_origin.py`, `bootstrap_family.py` | 3–5 h |
| `R2b_gpu_shared_budget.ps1` | second round: `shared_budget_study.py` (tuning, final runs, summary), with the safeguards of `P5c_gpu.ps1` | 1–2 days, GPU |
| `R2c_gpu_r1_rerun.ps1` | second round: the 12 R1 network runs of the shared budget repeated after the half-precision fix, then the summary again | 6–8 h, GPU |

Helpers in `runs/` that are not packages: `_common.ps1` (shared settings and helpers, see above), `gpu_check.py`
(GPU pre-flight check: runs a matrix product and a backward pass on the GPU and exits with code 0 only if they
succeed) and `keep_awake.ps1` (keeps Windows awake while a package runs in another window).

Run the GPU packages (P4, P5a–P5c, R2b, R2c) alone, with the charger connected. P4 needs
`q1_revision/published_control/data.parquet` (`published_protocol_control.py --build-only`, step 7 above), and P6
reads the outputs of all other packages.

## Release assets: stored predictions and models

Stored test predictions (`*.npz`: true and predicted class, class probabilities where stored, global row positions of
the test flows and their capture group), cached arrays and trained models (`*.pt`: network weights and the
standardisation of the shared-budget runs; `*.xgb.json`, `*.lgb.txt`: XGBoost and LightGBM models; the random forests
are not stored) are too large for git. They are attached as zip files to release **v2.0** of this repository
(`q1_revision_part1.zip`, `q1_revision_part2.zip`, `tree_protocol.zip`; 695 files, 2.45 GB, including the superseded
first-pass shared-budget runs), with `MANIFEST.json` (size and SHA-256 of every file). Unzip them into the repository folder: every file lands next to its result file. An archived release with a
DOI will follow on acceptance of the paper.

## Manifest and evaluation check

`manifest/runs.csv` has one line per model run (703 runs: every result file with a macro-F1, the 24 held-out
sub-attack runs, which report recalls, the 14 rule-sensitivity runs of `split_pilot/rule_sensitivity.json` and the 76
shared-budget runs; 605 with stored predictions, 66 with a stored model): result file, script, model,
configuration, training seed, sample (the 3,626,502 flows of `export_flags/flow_flags.csv.gz`, whose SHA-256 is in
`manifest/manifest.json`; the CICIDS2017 and published-setting samples are named), features, preprocessing (missing
values set to zero, or training medians for the XGBoost pilot and cleaning-variant analyses), class weights, split design
(with split seed or cut), training and test labels, sizes, macro-F1, balanced accuracy, accuracy, the release-asset
path of its predictions and model, and notes. The configuration is the one named by the run or, where the result file
names none, the fixed settings of its script. Runs of the first review rounds and the random forests stored no model;
they can be refitted from the script, configuration and seed (the refits of `r3_train_reference.py` and
`rolling_origin.py` reproduce the published tree-ensemble runs to the last digit). `manifest/paper_map.csv` lists every paragraph, caption and table of the paper with the
numbers it prints and the result files those numbers come from; `manifest/figures.csv` and `figures/values/` do the
same for the figures.

After unzipping the release assets:

```bash
python tools/evaluate_predictions.py
```

recomputes accuracy, balanced accuracy, macro-F1 and macro-AP of every run from its stored predictions and compares them
with its result file over the classes present in each run (`results_2026_03_03/evaluation_check.csv`; on the author's
machine: 593 runs with stored predictions and a macro-F1, of the tree, deep, training-only cleaning, R3, rolling-origin
and shared-budget studies, the superseded first-pass runs included; largest difference 2.2e-16).

## Figures

`figures/values/mid_F*_values.json` hold every value plotted in the six figures (unrounded, with the runs and seeds it
is computed from and its source files): F1 = Fig. 1 (study design), F5 = Fig. 2, F2 = Fig. 3, F4 = Fig. 4, F3 = Fig. 5
and Table 6, F6 = Fig. 6 and Table 5. In the revised manuscript the numeric panels of the former Figs. 5a-c (the
levels of the three metrics) and 6a (the controls) are printed as Tables 6 and 5, with the values of these files; the
`figure` column of `manifest/figures.csv` gives the printed table or figure of each part. The scripts that draw the
figures also assert every printed number against the manuscript sources and are therefore kept with them.

## Citation

```bibtex
@article{fadel2026identifier,
  title   = {Identifier Leakage, Folder Labels and Random Splits Distort the Evaluation of
             {IoT} Intrusion Detection: Evidence from {CIC IoT-DIAD} 2024},
  author  = {Fadel, Ali Hussein},
  journal = {International Journal of Intelligent Engineering and Systems},
  year    = {2026},
  note    = {Under review}
}
```

## Licence

Code: Apache License 2.0 (`LICENSE`). Result files: CC BY 4.0.

## Contact

Ali Hussein Fadel, Department of Computer Science, College of Science, University of Diyala, Iraq
(ali_hussein_fadel@uodiyala.edu.iq). Questions and issues are welcome via GitHub Issues.
