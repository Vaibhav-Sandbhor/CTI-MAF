import os
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.metrics import (roc_curve, auc, precision_recall_curve,
                             confusion_matrix, precision_score, recall_score)

# we avoid importing tensorflow here; predictions should be precomputed

# helpers for sequence creation (copied from train_model)
def create_sequences(X, y, seq_length):
    X_seq, y_seq = [], []
    for i in range(len(X) - seq_length):
        X_seq.append(X[i:i+seq_length])
        y_seq.append(y[i+seq_length])
    return np.array(X_seq), np.array(y_seq)


def load_data_and_model(root=None, seq_length=5, hold_family=None):
    # this function now just loads test labels and expects precomputed y_probs
    if root is None:
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    npz_path = os.path.join(root, "models", "analysis_inputs.npz")
    if not os.path.exists(npz_path):
        raise FileNotFoundError("run train_model.py first to save probabilities")
    arr = np.load(npz_path)
    y_test = arr['y_test']
    y_probs = arr['y_probs'].flatten()
    return y_probs, y_test


def threshold_engineering(X_test, y_test, model=None, probs=None, thresholds=None, plot=True):
    # if probabilities are provided, use them; otherwise run the model
    if probs is None:
        if model is None or X_test is None:
            raise ValueError("must supply either a model+X_test or precomputed probs")
        probs = model.predict(X_test).flatten()
    fpr, tpr, roc_th = roc_curve(y_test, probs)
    roc_auc = auc(fpr, tpr)
    prec, rec, pr_th = precision_recall_curve(y_test, probs)
    pr_auc = auc(rec, prec)

    if plot:
        plt.figure(figsize=(12,5))
        plt.subplot(1,2,1)
        plt.plot(fpr, tpr, label=f'ROC area = {roc_auc:.3f}')
        plt.plot([0,1],[0,1],'--',color='gray')
        plt.xlabel('FPR'); plt.ylabel('TPR'); plt.title('ROC curve'); plt.legend()
        plt.subplot(1,2,2)
        plt.plot(rec, prec, label=f'PR area = {pr_auc:.3f}')
        plt.xlabel('Recall'); plt.ylabel('Precision'); plt.title('Precision-Recall'); plt.legend()
        plt.tight_layout()
        plt.show()

    if thresholds is None:
        thresholds = np.linspace(0.1,0.9,81)

    results = []
    for t in thresholds:
        preds = (probs > t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
        recall = tp / (tp + fn) if (tp+fn)>0 else 0
        precision = tp / (tp + fp) if (tp+fp)>0 else 0
        fp_rate = fp / (fp + tn) if (fp+tn)>0 else 0
        fn_rate = fn / (fn + tp) if (fn+tp)>0 else 0
        results.append((t, recall, precision, fp_rate, fn_rate))
    df_res = pd.DataFrame(results, columns=['threshold','recall','precision','fp_rate','fn_rate'])
    return df_res


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Model evaluation and threshold engineering")
    parser.add_argument("--seq", type=int, default=5)
    parser.add_argument("--hold", default=None,
                        help="family to use for zero-day test; if omitted use all (or pass 'all' to run each family")
    parser.add_argument("--root", default=None)
    parser.add_argument("--benign-rate", type=float, default=10000,
                        help="simulated benign events per hour for runtime analysis")
    args = parser.parse_args()

    # if hold='all' run leave-one-family-out evaluation
    if args.hold == 'all':
        df = pd.read_csv(os.path.join(args.root or os.getcwd(), "data", "processed", "ransomware_features.csv"))
        families = [f for f in df['family'].unique() if f != 'benign']
        print("Family-wise zero-day evaluation")
        for fam in families:
            print(f"\n--- testing holdout {fam} ---")
            y_probs, y_test = load_data_and_model(root=args.root,
                                                   seq_length=args.seq,
                                                   hold_family=fam)
            df_thresh = threshold_engineering(None, y_test, probs=y_probs, plot=False)
            candidates = df_thresh[(df_thresh['recall']>=0.85) & (df_thresh['fp_rate']<=0.15)]
            if not candidates.empty:
                best = candidates.loc[candidates['recall'].idxmax()]
                print(" Suggested threshold:", best.to_dict())
            else:
                print(" no threshold meets criteria")
            simulate_runtime(df_thresh, args.benign_rate)
        return

    # single test
    y_probs, y_test = load_data_and_model(root=args.root,
                                           seq_length=args.seq,
                                           hold_family=None if args.hold in (None, 'all') else args.hold)
    # calibration plot
    plot_calibration(y_test, y_probs)
    df_thresh = threshold_engineering(None, y_test, probs=y_probs)
    # look for candidate thresholds
    candidates = df_thresh[(df_thresh['recall']>=0.85) & (df_thresh['fp_rate']<=0.15)]
    if not candidates.empty:
        best = candidates.loc[candidates['recall'].idxmax()]
        print("Suggested threshold:", best.to_dict())
    else:
        print("no threshold meets recall>=0.85 and fp_rate<=0.15")
    csv_path = os.path.join(args.root or '.', 'threshold_scan.csv')
    df_thresh.to_csv(csv_path, index=False)
    print("threshold scan written to", csv_path)
    simulate_runtime(df_thresh, args.benign_rate)


# calibration curve utility
from sklearn.calibration import calibration_curve

def plot_calibration(y_test, y_probs):
    prob_true, prob_pred = calibration_curve(y_test, y_probs, n_bins=10)
    plt.figure()
    plt.plot(prob_pred, prob_true, marker='o')
    plt.plot([0,1],[0,1],'--', color='gray')
    plt.xlabel('Mean predicted probability')
    plt.ylabel('Fraction of positives')
    plt.title('Calibration curve')
    plt.show()

# runtime simulation
def simulate_runtime(df_thresh, benign_rate):
    # take threshold with recall >=0.85 and minimum fp_rate
    selection = df_thresh[df_thresh['recall']>=0.85]
    if selection.empty:
        print("cannot simulate runtime, no threshold meets recall>=0.85")
        return
    row = selection.loc[selection['fp_rate'].idxmin()]
    thr = row['threshold']
    fp_rate = row['fp_rate']
    alerts = fp_rate * benign_rate
    print(f"runtime simulation @ threshold {thr:.2f}: fp_rate={fp_rate:.3f}, alert rate~{alerts:.0f}/hour")

if __name__ == '__main__':
    main()
