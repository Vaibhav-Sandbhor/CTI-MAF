import os
import numpy as np
import pandas as pd

OUT_DIR = "ransomware_module/data/raw/benign/generated"
os.makedirs(OUT_DIR, exist_ok=True)

NUM_SAMPLES = 30
WINDOWS = 15

def generate_benign_sample(idx):
    rows = []
    timestamp = 0

    for _ in range(WINDOWS):
        rows.append({
            "ata_entropy_avg": np.random.uniform(0.1, 0.4),
            "mem_entropy_avg": np.random.uniform(0.1, 0.4),
            "disk_write_ratio": np.random.uniform(0.05, 0.2),
            "mem_write_ratio": np.random.uniform(0.05, 0.2),
            "label": 0
        })
        timestamp += 1

    df = pd.DataFrame(rows)
    df.to_csv(f"{OUT_DIR}/benign_{idx}.csv", index=False)

def main():
    for i in range(NUM_SAMPLES):
        generate_benign_sample(i)

    print("[+] Benign samples generated:", NUM_SAMPLES)

if __name__ == "__main__":
    main()
