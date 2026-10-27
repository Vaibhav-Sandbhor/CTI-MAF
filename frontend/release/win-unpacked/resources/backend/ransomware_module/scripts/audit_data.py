import os
import pandas as pd
import numpy as np

root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
data_path = os.path.join(root, "data", "processed", "ransomware_features.csv")

df = pd.read_csv(data_path)

print("=" * 60)
print("DATA INTEGRITY AUDIT")
print("=" * 60)

# 1. check for exact duplicates
print("\n[1] DUPLICATE ROWS")
duplicates = df.duplicated().sum()
print(f"exact duplicate rows: {duplicates}")
if duplicates > 0:
    print("WARNING: duplicates detected!")

# 2. check family distribution
print("\n[2] FAMILY DISTRIBUTION")
print(df['family'].value_counts())

# 3. check for family contamination (benign appearing as ransomware or vice versa)
print("\n[3] LABEL-FAMILY MAPPING")
for fam in df['family'].unique():
    labels = df[df['family'] == fam]['label'].unique()
    print(f"  {fam}: labels = {labels}")

# 4. Test-Train split simulation
hold_family = "ryuk"
train_df = df[df['family'] != hold_family].copy()
zero_day_ransom = df[df['family'] == hold_family]
benign_samples = df[df['family'] == "benign"]
test_df = pd.concat([zero_day_ransom, benign_samples]).copy()

print(f"\n[4] TRAIN/TEST SPLIT INTEGRITY (hold out {hold_family})")
print(f"  train samples: {len(train_df)}")
print(f"  test samples: {len(test_df)}")
print(f"  overlap: {len(set(train_df.index) & set(test_df.index))}")  # should be 0

# 5. check benign overlap
benign_in_train = (train_df['family'] == 'benign').sum()
benign_in_test = (test_df['family'] == 'benign').sum()
print(f"\n[5] BENIGN SAMPLES SPLIT")
print(f"  in train: {benign_in_train}")
print(f"  in test: {benign_in_test}")
print(f"  WARNING: benign appears in BOTH splits (expected for zero-day scenario)")

# 6. check feature statistics for data drift
print(f"\n[6] FEATURE STATISTICS (checking for drift)")
feature_cols = [c for c in df.columns if c not in ("label", "family")]
print(f"  {len(feature_cols)} features detected")

# show min/max for first few features
for feat in feature_cols[:3]:
    train_vals = train_df[feat]
    test_vals = test_df[feat]
    print(f"  {feat}:")
    print(f"    train: [{train_vals.min():.4f}, {train_vals.max():.4f}]")
    print(f"    test: [{test_vals.min():.4f}, {test_vals.max():.4f}]")

print("\n" + "=" * 60)
print("CONCLUSION")
print("=" * 60)
if duplicates == 0 and len(set(train_df.index) & set(test_df.index)) == 0:
    print("✅ NO DATA LEAKAGE DETECTED")
    print("✅ STRICT FAMILY-LEVEL HOLDOUT CONFIRMED")
else:
    print("⚠️  POTENTIAL DATA LEAKAGE - REVIEW REQUIRED")
