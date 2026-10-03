# Release checklist

What this repository already holds: the code of every experiment (`experiments/`, `src/`), the result files of every
run (`results_2026_03_03/`), the per-flow rule flags and split assignments
(`results_2026_03_03/q1_revision/export_flags/flow_flags.csv.gz`), the 472-flow audit sample with the decisions,
instructions and evidence briefs of the language-model annotators (`results_2026_03_03/q1_revision/rule_validation2/`),
and the run packages (`runs/`).

On acceptance (the Data availability statement of the paper promises these with the published version):

1. Add the figure scripts and the values plotted in every figure (kept private while the paper is under review).
2. Pack the large result files (stored test predictions and model weights, about 1.1 GB in two zip files below the
   2 GB asset limit, with `dist/release_assets/MANIFEST.json`). The files are in the working copy in which the
   experiments were run, so point the packer to it:
   `python tools/make_release_assets.py --source "<folder of that working copy>"`
3. Create a GitHub Release (for example `v1.0`) and attach the zip files and `MANIFEST.json`.
4. Archive the release with a DOI (Zenodo's GitHub integration creates one for every release once the repository is
   enabled on zenodo.org).
5. Put the DOI into the Citation section of `README.md` and into the paper's Data availability statement.
