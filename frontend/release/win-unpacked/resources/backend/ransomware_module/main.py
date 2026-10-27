import os
import pandas as pd
from ransomware_module.features.feature_extractor import extract_features

BASE = "ransomware_module/data/raw"
OUTPUT_DIR = "ransomware_module/output"


def main():
    print("[+] Starting Ransomware Detection Module")

    dfs = []

    ransomware_families = ["ryuk", "lockbit", "conti", "revil"]

    # ---- Ransomware samples ----
    for family in ransomware_families:
        folder = os.path.join(BASE, "ransomware", family)
        if os.path.exists(folder):
            print(f"[+] Processing ransomware family: {family}")
            dfs.append(extract_features(folder, 1))
        else:
            print(f"[-] Folder not found: {folder}")

    # ---- Benign samples ----
    benign_folder = os.path.join(BASE, "benign")
    if os.path.exists(benign_folder):
        print("[+] Processing benign samples")
        dfs.append(extract_features(benign_folder, 0))

    if not dfs:
        print("[-] No datasets found. Exiting.")
        return

    # ✅ df is created FIRST
    df = pd.concat(dfs, ignore_index=True)

    print(f"[+] Dataset shape: {df.shape}")

    # ---- (Optional sanity split – now SAFE) ----
    ransom = df[df["label"] == 1]
    benign = df[df["label"] == 0]

    print(f"[+] Ransomware samples: {len(ransom)}")
    print(f"[+] Benign samples: {len(benign)}")

    # ---- Save ----
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_file = os.path.join(OUTPUT_DIR, "ransomware_features.csv")
    df.to_csv(out_file, index=False)

    print(f"[+] Feature dataset saved to {out_file}")


if __name__ == "__main__":
    main()
