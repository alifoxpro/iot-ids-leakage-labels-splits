# Release checklist

What git holds: the code of every experiment (`experiments/`, `src/`), the run packages (`runs/`), the result files of
every run (`results_2026_03_03/`), the per-flow rule flags and split assignments
(`results_2026_03_03/q1_revision/export_flags/flow_flags.csv.gz`), the 472-flow audit sample with its sampling design and
the decisions, instructions and evidence briefs of the language-model annotators
(`results_2026_03_03/q1_revision/rule_validation2/`), the source values of every figure (`figures/values/`), the
manifest (`manifest/`), the evaluation check (`tools/evaluate_predictions.py`) and the software environment
(`environment.yml`, `requirements-lock.txt`).

Release v2.0 (second review round): the large files, as release assets.

1. Pack the stored test predictions and the trained models. They are in the working copy in which the experiments were
   run, so point the packer to it:
   `python tools/make_release_assets.py --source "<folder of that working copy>"`
   (zip files below the 2 GB asset limit in `dist/release_assets/`, with `MANIFEST.json`: size and SHA-256 of every file)
2. Rebuild the manifest with the same source: `python tools/build_manifest.py --source "<folder of that working copy>"`,
   and commit it.
3. Create the GitHub Release `v2.0` on the commit of step 2 and attach the zip files and `MANIFEST.json`
   (github.com -> Releases -> Draft a new release; the files are uploaded in the browser).
4. On acceptance: archive a release with a DOI (Zenodo's GitHub integration creates one for every release once the
   repository is enabled on zenodo.org) and put the DOI into the Citation section of `README.md`.
