# Rule audit by language-model annotators (Section 3.3 of the manuscript)

The 472 flows of `../audit_sample.csv` (stratified sample of flows flagged and kept by R1, R2, R3 and their union)
were labelled `attack`, `background` or `unclear` by language-model annotators only. **No human checked any
label.** All roles (annotators A and B, the adjudicator and the third annotator C) were separate sessions of the
same language model; model, dates and source of this record: `provenance.json`.

| Path | Content |
|---|---|
| `pack/` | what the annotators were given: instructions (`README_annotators.md`, released copy with one added note), evidence briefs per class (`evidence_<class>.md`), the 19 batch files (`batch_*.md`), the 40-flow spot check of C (`spotcheck.md`) and `pack_manifest.json` |
| `annotator_A/`, `annotator_B/` | the filled batch files of A and B |
| `annotator_C/spotcheck_third.csv` | labels and evidence of C for the 40 spot-check flows |
| `annotator_outputs.json`, `annotations_AB_raw.tsv` | the decisions of A and B as imported |
| `adjudications.json` | the adjudicator's decisions on the 12 flows on which A and B disagreed |
| `annotations.csv`, `final_decisions.csv` | decisions and evidence of A and B and the final decision for every flow |
| `agreement.json` | agreement of A and B before adjudication (Cohen's kappa with bootstrap interval) |
| `audit_template_blind_filled.md`, `audit_scores.json`, `audit_scores.csv` | the final decisions in the audit template and their scores per class and rule |
| `audit_summary.json` | precision, kept attack share, estimated false-removal rate with Jeffreys intervals (Monte Carlo and, without Monte Carlo error, by numerical integration; the manuscript uses the latter) |
| `provenance.json` | language model, dates and roles of the annotation |
| `first_pass_20260930/` | the first annotation pass: the workflow was interrupted while only the final assembly was pending and was resumed, so batches 10-19 of A and B were annotated a second time in new sessions with the same instructions; the labels above are those of the second pass. 11 of the 472 final decisions differ from the first pass, all between unclear and background (none involves attack); see its `README.md` |

`../audit_author_review_50.md` and `../audit_author_review_50.xlsx` are unused templates for a planned check of
50 flows by the author; that check was not carried out and the templates are empty.
