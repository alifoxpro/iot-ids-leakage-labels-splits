Superseded runs of shared_budget_study.py (moved here on 2026-10-18; kept for transparency, not used in the paper).

These 12 final runs (ResNet1D, GRU, Transformer and MLP; R1 labels; seeds 42, 17, 7) were trained with a
validation loss that was NaN in every epoch: one R1 in-period validation flow (a DOS flow whose feat_min lies
1.2e5 standard deviations from the training mean) overflowed half precision in the AMP validation pass. Early
stopping therefore never saw a finite loss and every run stopped after the 10-epoch patience with its final
weights. Their test scores were computed in single precision and are correct for those 10-epoch weights, but
the runs did not follow the predeclared protocol (early stopping on the in-period validation loss).

The 1-D CNN (its valid convolutions and pooling never reach the last three features), all raw-label runs and all
tuning runs had finite validation losses and were kept. deep_protocol_study.train now evaluates a validation
chunk with a non-finite half-precision loss again in single precision; the 12 runs were then run again
(runs/R2c_gpu_r1_rerun.ps1) into ../final/. Diagnosis: 1 of 454,907 validation flows exceeded the fp16 range
after standardisation (max |x| 1.231e5, column 78 feat_min); under fp32 its logits are finite.
