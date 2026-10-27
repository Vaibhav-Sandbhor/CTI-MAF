Evaluation Summary
==================

Files produced (latest):

- family_evaluation_merged_20260221_184654.json — merged LOFO results + surrogate importances
- family_evaluation_20260221_175154_with_importance_20260221_184654.txt — human-readable report with appended surrogate feature importance
- feature_importance_lofo_20260221_184434.csv — RandomForest surrogate top-5 features per LOFO fold
- feature_importance_lofo_plot.png — comparative bar plot of top-5 importances per held-out family

Key findings (high level):

- Leave-One-Family-Out (LOFO) evaluation shows strong cross-family generalization (ROC AUC ≈ 0.996–0.997, recall ≈ 0.98–0.99 across folds).
- Single-family stress tests indicate the model generalizes well even when trained on a single family (varies by family; conti best, ryuk weakest).
- Surrogate feature importances (RandomForest on flattened sequences) are consistent across families. Top features: `mem_write_delta_mean`, `total_disk_writes`, `disk_write_delta_mean`, `ata_variance`, `mem_entropy_avg`.

Recommended next steps (pick one):

1. Run model-native permutation importance (slow) to verify surrogate results.
2. Generate SHAP explanations via a gradient-boosting surrogate (faster) for per-sample explanations.
3. Integrate results into documentation or presentation assets.

How to reproduce the evaluation:

```powershell
python scripts\comprehensive_family_evaluation.py
python scripts\extract_surrogate_feature_importance.py
python scripts\merge_and_visualize_importances.py
```

If you want, I can now:

- Run the slow permutation-importance on the TF models (will be much slower but yields model-native importances), or
- Generate SHAP explanations via an XGBoost surrogate and save per-fold SHAP summary plots.

Which should I do next? If you prefer, I can proceed with option 1 or 2 automatically.
