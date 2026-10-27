import argparse
import subprocess
import itertools
import csv
import os
import re

# This script performs a simple grid search by invoking the existing
# `train_model.py` CLI with different hyperparameter settings.  It
# captures the zero-day F1/ROC-AUC printed by train_model and writes a
# CSV summary to `evaluation_reports/hyperparam_results.csv`.

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_DIR = os.path.join(ROOT, "evaluation_reports")
os.makedirs(REPORT_DIR, exist_ok=True)

parser = argparse.ArgumentParser(description="Hyperparameter grid search for LSTM ransomware detector")
parser.add_argument("--epochs", type=int, default=3, help="number of epochs to train for each trial")
parser.add_argument("--oversample", action="store_true", help="pass --oversample to training runs")
parser.add_argument("--pos-weight", type=float, default=1.0, help="positive class weight to use (same for all runs unless grid includes it)")
parser.add_argument("--seed", type=int, default=42, help="random seed to pass to training runs")
parser.add_argument("--grid-file", help="path to JSON file containing a dict of parameter lists to use as grid")
args = parser.parse_args()

# default grid
default_grid = {
    "learning_rate": [1e-3, 5e-4, 1e-4],
    "dropout": [0.2, 0.3, 0.5],
    "batch_size": [128, 256, 512],
    "seq": [5, 10],
    "pos_weight": [1.0, 3.0],
    "loss": ["binary_crossentropy", "focal"],
    "gamma": [1.0, 2.0, 4.0],
    # units tuple (first LSTM layer, second LSTM layer)
    "units": [(64, 32), (128, 64)],
}

if args.grid_file:
    import json
    with open(args.grid_file, "r", encoding="utf-8") as f:
        grid = json.load(f)
else:
    grid = default_grid

# build list of parameter names and values
param_names = list(grid.keys())
param_values = [grid[name] for name in param_names]

# open output csv
out_path = os.path.join(REPORT_DIR, "hyperparam_results.csv")
with open(out_path, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    header = param_names + ["f1", "roc_auc", "threshold", "stdout"]
    writer.writerow(header)

    # iterate grid
    for combo in itertools.product(*param_values):
        combo_dict = dict(zip(param_names, combo))
        # assemble command line
        cmd = ["python", "scripts/train_model.py"]
        cmd += ["--epochs", str(args.epochs)]
        cmd += ["--batch", str(combo_dict.get("batch_size"))]
        cmd += ["--seq", str(combo_dict.get("seq"))]
        cmd += ["--pos-weight", str(combo_dict.get("pos_weight"))]
        cmd += ["--seed", str(args.seed)]
        if args.oversample:
            cmd.append("--oversample")
        # add learning rate and dropout by environment hack (modify via env?)
        # train_model doesn't accept LR or dropout; we can set via env variable
        env = os.environ.copy()
        env["TF_LEARNING_RATE"] = str(combo_dict.get("learning_rate"))
        env["TF_DROPOUT"] = str(combo_dict.get("dropout"))
        # units encoded as "u1,u2"
        units = combo_dict.get("units")
        env["TF_UNITS"] = ",".join(str(u) for u in units)

        print("Running trial:", combo_dict)
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        output = result.stdout + "\n" + result.stderr

        # parse metrics
        f1 = None
        auc = None
        thresh = None
        m = re.search(r"optimal threshold.*f1=([0-9\.]+)", output)
        if m:
            f1 = float(m.group(1))
            thresh = float(re.search(r"optimal threshold.*: ([0-9\.]+)", output).group(1))
        m = re.search(r"Zero-Day ROC AUC:\s*([0-9\.]+)", output)
        if m:
            auc = float(m.group(1))

        writer.writerow([combo_dict.get(name) for name in param_names] + [f1, auc, thresh, output.replace("\n","\\n")])

print("Grid search complete, results stored in", out_path)
