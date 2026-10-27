import os
import pandas as pd
from ransomware_module.features.temporal_feature_extractor import extract_temporal_features

RAW_BASE = "ransomware_module/data/raw"
OUT_FILE = "ransomware_module/data/processed/temporal_features.csv"

FAMILIES = {
    "conti": 1,
    "lockbit": 1,
    "ryuk": 1,
    "revil": 1
}

def main():
    all_dfs = []

    for fam, label in FAMILIES.items():
        fam_path = os.path.join(RAW_BASE, "ransomware", fam)
        for sample in os.listdir(fam_path):
            sample_path = os.path.join(fam_path, sample)
            df = extract_temporal_features(sample_path, label)
            if df is not None:
                all_dfs.append(df)

    final_df = pd.concat(all_dfs, ignore_index=True)
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    final_df.to_csv(OUT_FILE, index=False)
    print("[+] Temporal dataset saved:", OUT_FILE)
    print("[+] Shape:", final_df.shape)

if __name__ == "__main__":
    main()
