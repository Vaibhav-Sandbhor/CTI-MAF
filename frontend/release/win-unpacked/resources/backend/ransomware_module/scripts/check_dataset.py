import pandas as pd

DATA_PATH = "ransomware_module/data/processed/ransomware_features.csv"

df = pd.read_csv(DATA_PATH)

print("\n===== DATASET SUMMARY =====")
print("Total samples:", len(df))
print("\nLabel distribution:")
print(df['label'].value_counts())

print("\nFamily distribution:")
print(df['family'].value_counts())

print("\nFeature statistics:")
print(df.describe())

print("\nAny missing values?")
print(df.isnull().sum())

print("\nDone.")
