"""One-shot patcher: adds sklearn MLP fallback to train_model.py"""
import sys, re
from pathlib import Path

SRC = Path("ransomware_module/scripts/train_model.py")

with open(SRC, encoding="utf-8") as f:
    content = f.read()

if "train_sklearn" in content:
    print("Already patched.")
    sys.exit(0)

SKLEARN_BLOCK = r"""# ============================================================
# sklearn MLP fallback (auto-used when TF DLL unavailable)
# ============================================================

def _tf_available() -> bool:
    import subprocess
    try:
        subprocess.check_call([sys.executable, "-c", "import tensorflow"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        return True
    except Exception:
        return False


def _sk_find_threshold(probs, y):
    best_thr, best_f1 = 0.5, 0.0
    for t in __import__("numpy").linspace(0.05, 0.95, 100):
        p  = (probs >= t).astype(int)
        tp = int(((p == 1) & (y == 1)).sum())
        fp = int(((p == 1) & (y == 0)).sum())
        fn = int(((p == 0) & (y == 1)).sum())
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec  = tp / (tp + fn) if (tp + fn) else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        if f1 > best_f1:
            best_f1, best_thr = f1, float(t)
    print("[TRAIN] Optimal threshold:", round(best_thr,4), "F1:", round(best_f1,4))
    return best_thr


def _sk_evaluate(probs, y, thr):
    _np = __import__("numpy")
    p  = (probs >= thr).astype(int)
    tp = int(((p==1)&(y==1)).sum()); tn = int(((p==0)&(y==0)).sum())
    fp = int(((p==1)&(y==0)).sum()); fn = int(((p==0)&(y==1)).sum())
    tot = tp+tn+fp+fn
    acc  = (tp+tn)/tot if tot else 0.0
    prec = tp/(tp+fp)  if (tp+fp) else 0.0
    rec  = tp/(tp+fn)  if (tp+fn) else 0.0
    fpr  = fp/(fp+tn)  if (fp+tn) else 0.0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec) else 0.0
    print("\n[TRAIN] MLP Test Metrics:")
    print("  Accuracy :", round(acc,4),  "[OK]" if acc>=0.95 else "[WARN target >0.95]")
    print("  Precision:", round(prec,4)); print("  Recall   :", round(rec,4), "[OK]" if rec>=0.95 else "[WARN]")
    print("  F1       :", round(f1,4));   print("  FPR      :", round(fpr,4))
    print("  TP=%d TN=%d FP=%d FN=%d" % (tp,tn,fp,fn))
    return {"accuracy":round(acc,4),"precision":round(prec,4),"recall":round(rec,4),
            "f1":round(f1,4),"fpr":round(fpr,4),"tp":tp,"tn":tn,"fp":fp,"fn":fn}


def train_sklearn(data_path=None, seed=42):
    import json as _json, numpy as _np
    from sklearn.neural_network import MLPClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    if data_path is None:
        data_path = DEFAULT_DATA
    _np.random.seed(seed)
    _MODELS_DIR.mkdir(parents=True, exist_ok=True)
    df = load_data(data_path)
    feat_cols = [c for c in BEHAVIORAL_FEATURES if c in df.columns]
    X = df[feat_cols].fillna(0).values.astype(_np.float32)
    y = df["label"].values.astype(_np.float32)
    idx = _np.random.permutation(len(X))
    X, y = X[idx], y[idx]
    sc = StandardScaler()
    Xs = sc.fit_transform(X).astype(_np.float32)
    X_tr,X_te,y_tr,y_te = train_test_split(Xs,y,test_size=0.15,random_state=seed,stratify=y)
    X_tr,X_va,y_tr,y_va = train_test_split(X_tr,y_tr,test_size=0.15,random_state=seed,stratify=y_tr)
    print("[TRAIN] sklearn split: train=%d val=%d test=%d" % (len(X_tr),len(X_va),len(X_te)))
    print("[TRAIN] Training MLPClassifier (sklearn fallback -- TF unavailable)...")
    mlp = MLPClassifier(hidden_layer_sizes=(128,64,32),activation="relu",solver="adam",
        alpha=1e-4,learning_rate_init=1e-3,max_iter=300,early_stopping=True,
        validation_fraction=0.1,n_iter_no_change=15,random_state=seed,verbose=True)
    mlp.fit(X_tr, y_tr)
    vp  = mlp.predict_proba(X_va)[:,1].astype(_np.float32)
    tp2 = mlp.predict_proba(X_te)[:,1].astype(_np.float32)
    thr = _sk_find_threshold(vp,  y_va.astype(_np.float32))
    mtr = _sk_evaluate(tp2, y_te.astype(_np.float32), thr)
    mlp_path = _MODELS_DIR / "mlp_model.pkl"
    import joblib as _jl
    _jl.dump(mlp, str(mlp_path)); _jl.dump(sc, str(SCALER_OUT))
    THRESHOLD_OUT.write_text(str(thr))
    HISTORY_OUT.write_text(_json.dumps({"loss_curve":[float(v) for v in mlp.loss_curve_],
        "test_metrics":mtr,"backend":"sklearn_mlp","threshold":thr,"n_iter":mlp.n_iter_},indent=2))
    print("[TRAIN] Saved:", mlp_path, "|", SCALER_OUT, "| thr:", round(thr,4))
    print("[TRAIN] sklearn MLP training complete.")


"""

# Find insertion point: just before 'def train('
marker = "\ndef train(\n"
idx = content.find(marker)
if idx == -1:
    print("ERROR: marker not found")
    sys.exit(1)

# Insert sklearn block before train()
patched = content[:idx+1] + SKLEARN_BLOCK + content[idx+1:]

# Also patch the body of train() to check for TF availability first
# Find "    import tensorflow as tf\n\n    tf.random.set_seed(seed)"
OLD_TF_IMPORT = "    import tensorflow as tf\n\n    tf.random.set_seed(seed)"
NEW_TF_IMPORT = "    if not _tf_available():\n        print(\"[TRAIN] TF unavailable -- using sklearn MLP\")\n        train_sklearn(data_path, seed=seed)\n        return\n    import tensorflow as tf\n\n    tf.random.set_seed(seed)"
patched = patched.replace(OLD_TF_IMPORT, NEW_TF_IMPORT, 1)

# Update train() signature to add force_sklearn param
OLD_SIG = '    seed:       int   = 42,\n) -> None:'
NEW_SIG = '    seed:          int   = 42,\n    force_sklearn: bool  = False,\n) -> None:'
patched = patched.replace(OLD_SIG, NEW_SIG, 1)

# Update TF check to respect force_sklearn
OLD_TF_CHECK = '    if not _tf_available():\n        print("[TRAIN] TF unavailable -- using sklearn MLP")\n        train_sklearn(data_path, seed=seed)\n        return'
NEW_TF_CHECK = '    if force_sklearn or not _tf_available():\n        reason = "forced" if force_sklearn else "TF DLL unavailable"\n        print("[TRAIN] Using sklearn MLP (" + reason + ")")\n        train_sklearn(data_path, seed=seed)\n        return'
patched = patched.replace(OLD_TF_CHECK, NEW_TF_CHECK, 1)

# Update parser to add --force-sklearn
OLD_PARSER = '    p.add_argument("--seed",       type=int, default=42)\n    return p'
NEW_PARSER = '    p.add_argument("--seed",       type=int, default=42)\n    p.add_argument("--force-sklearn", action="store_true",\n                   help="use sklearn MLP instead of TF LSTM")\n    return p'
patched = patched.replace(OLD_PARSER, NEW_PARSER, 1)

# Update main() to pass force_sklearn
OLD_CALL = '        seq_len=args.seq_len,\n        seed=args.seed,\n    )'
NEW_CALL = '        seq_len=args.seq_len,\n        seed=args.seed,\n        force_sklearn=getattr(args, "force_sklearn", False),\n    )'
patched = patched.replace(OLD_CALL, NEW_CALL, 1)

with open(SRC, "w", encoding="utf-8") as f:
    f.write(patched)

print("Patched successfully.")
print("Has _tf_available:", "_tf_available" in patched)
print("Has train_sklearn:", "train_sklearn" in patched)
print("Has force_sklearn:", "force_sklearn" in patched)
print("Lines:", patched.count("\n"))
