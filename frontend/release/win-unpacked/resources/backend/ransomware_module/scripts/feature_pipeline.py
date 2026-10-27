import os
import pandas as pd
from ransomware_module.features.feature_extractor import extract_features

RAW_DIR = "ransomware_module/data/raw"
OUT_DIR = "ransomware_module/data/processed"

os.makedirs(OUT_DIR, exist_ok=True)


def run_pipeline():
    dfs = []

    ransomware_dir = os.path.join(RAW_DIR, "ransomware")
    benign_dir = os.path.join(RAW_DIR, "benign")

    # ==========================================================
    # 🔴 RANSOMWARE EXTRACTION
    # Structure:
    # ransomware/
    #     family/
    #         sample/
    #             ata_write.csv
    #             mem_write.csv
    # ==========================================================
    print("[+] Extracting ransomware features...")
    ransomware_count = 0

    for family in os.listdir(ransomware_dir):
        family_path = os.path.join(ransomware_dir, family)

        if not os.path.isdir(family_path):
            continue

        for sample in os.listdir(family_path):
            sample_path = os.path.join(family_path, sample)

            if not os.path.isdir(sample_path):
                continue

            df = extract_features(
                sample_path,
                label=1,
                family_name=family
            )

            if df is not None and not df.empty:
                dfs.append(df)
                ransomware_count += len(df)

    print(f"[+] Total ransomware samples extracted: {ransomware_count}")

    # ==========================================================
    # 🟢 BENIGN EXTRACTION (recursive)
    # benign/
    #     benign.csv
    #     generated/
    #         file1.csv
    #         file2.csv
    # ==========================================================
    print("[+] Extracting benign features (recursive)...")
    benign_count = 0

    for root, _, files in os.walk(benign_dir):
        for file in files:
            if not file.endswith(".csv"):
                continue

            file_path = os.path.join(root, file)

            df = extract_features(
                file_path,
                label=0,
                family_name="benign"
            )

            if df is not None and not df.empty:
                dfs.append(df)
                benign_count += len(df)

    print(f"[+] Total benign samples extracted: {benign_count}")

    # ==========================================================
    # FINAL SAVE
    # ==========================================================
    if len(dfs) == 0:
        raise RuntimeError("No features extracted. Check dataset structure.")

    final_df = pd.concat(dfs, ignore_index=True)

    output_path = os.path.join(OUT_DIR, "ransomware_features.csv")
    final_df.to_csv(output_path, index=False)

    print("[+] Base feature dataset saved")
    print("[+] Static label distribution:")
    print(final_df["label"].value_counts())

    print("\n[+] Columns:")
    print(list(final_df.columns))


if __name__ == "__main__":
    run_pipeline()
