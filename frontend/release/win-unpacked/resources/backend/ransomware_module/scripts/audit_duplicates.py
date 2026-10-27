import os
import pandas as pd
import numpy as np

root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
data_path = os.path.join(root, "data", "processed", "ransomware_features.csv")

df = pd.read_csv(data_path)

print("=" * 60)
print("DUPLICATE INSPECTION")
print("=" * 60)

# find which rows are duplicated
dup_mask = df.duplicated(keep=False)
duplicates_df = df[dup_mask].sort_values(by=list(df.columns))

print(f"\nTotal duplicate instances: {dup_mask.sum()}")
print(f"\nFirst 10 duplicates:")
print(duplicates_df.head(10))

# breakdown by family
print("\nDuplicates by family:")
print(duplicates_df['family'].value_counts())

# check if duplicates cross families
print("\nAre duplicates within same family or across?")
feature_cols = [c for c in df.columns if c not in ("label", "family")]
for feat_subset in [feature_cols[:3]]:  # check first 3 features
    dup_data = df[dup_mask][feature_cols + ['family', 'label']]
    grouped = dup_data.groupby(feature_cols)
    multi_family = grouped['family'].apply(lambda x: len(x.unique()) > 1).sum()
    print(f"  duplicates spanning multiple families: {multi_family}")
    if multi_family > 0:
        print("  ⚠️  POTENTIAL LEAKAGE if these cross train/test boundary")

# check if any duplicate crosses ryuk(test) and conti/lockbit/revil(train)
print("\nCross-family duplicate check (ryuk vs others):")
ryuk_dups = set(df[(df['family'] == 'ryuk') & dup_mask].index)
train_dups = set(df[(df['family'].isin(['conti','lockbit','revil'])) & dup_mask].index)
cross_contamination = len(ryuk_dups & train_dups)
print(f"  duplicates in both ryuk and training families: {cross_contamination}")
if cross_contamination > 0:
    print("  ⚠️  ACTUAL LEAKAGE DETECTED!")
else:
    print("  ✅ no cross-contamination between zero-day family and training families")

print("\n" + "=" * 60)
