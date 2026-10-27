import os
import pandas as pd

WINDOW_NS = 1_000_000_000  # 1 second window

def extract_temporal_features(sample_path, label):
    ata_file = os.path.join(sample_path, "ata_write.csv")
    mem_file = os.path.join(sample_path, "mem_write.csv")

    if not os.path.exists(ata_file) or not os.path.exists(mem_file):
        return None

    ata = pd.read_csv(ata_file, header=None)
    mem = pd.read_csv(mem_file, header=None)

    ata.columns = ["sec", "ns", "lba", "size", "entropy", "_"]
    mem.columns = ["sec", "ns", "gpa", "size", "entropy", "type"]

    ata["timestamp"] = ata["sec"] * 1e9 + ata["ns"]
    mem["timestamp"] = mem["sec"] * 1e9 + mem["ns"]

    start = min(ata["timestamp"].min(), mem["timestamp"].min())
    end = max(ata["timestamp"].max(), mem["timestamp"].max())

    rows = []
    t = start

    while t < end:
        ata_w = ata[(ata["timestamp"] >= t) & (ata["timestamp"] < t + WINDOW_NS)]
        mem_w = mem[(mem["timestamp"] >= t) & (mem["timestamp"] < t + WINDOW_NS)]

        rows.append({
            "disk_write_count": len(ata_w),
            "disk_entropy_avg": ata_w["entropy"].mean() if not ata_w.empty else 0,
            "mem_write_count": len(mem_w),
            "mem_entropy_avg": mem_w["entropy"].mean() if not mem_w.empty else 0,
            "label": label
        })

        t += WINDOW_NS

    return pd.DataFrame(rows)
