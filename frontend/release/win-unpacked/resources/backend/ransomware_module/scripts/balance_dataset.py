import pandas as pd
from sklearn.utils import resample
import os

INPUT_FILE = "ransomware_module/data/processed/ransomware_features.csv"
OUTPUT_FILE = "ransomware_module/data/processed/ransomware_features_balanced.csv"

def balance_dataset():
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError("Feature file not found. Run feature_pipeline first.")

    df = pd.read_csv(INPUT_FILE)

    ransomware = df[df["label"] == 1]
    benign = df[df["label"] == 0]

    print("[*] Original distribution:")
    print(df["label"].value_counts())

    if len(benign) == 0:
        raise RuntimeError("No benign samples available. Cannot balance.")

    # Upsample minority class (benign)
    benign_upsampled = resample(
        benign,
        replace=True,
        n_samples=len(ransomware),
        random_state=42
    )

    balanced_df = pd.concat([ransomware, benign_upsampled])
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)

    balanced_df.to_csv(OUTPUT_FILE, index=False)

    print("[+] Balanced dataset saved")
    print("[+] New distribution:")
    print(balanced_df["label"].value_counts())

if __name__ == "__main__":
    balance_dataset()
