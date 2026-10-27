import pandas as pd

def extract_features(csv_path, label):
    df = pd.read_csv(csv_path, header=None)

    features = {
        "mean_size": df[3].mean(),
        "std_size": df[3].std(),
        "entropy_mean": df[4].mean() if df.shape[1] > 4 else 0,
        "ops_count": len(df),
        "label": label
    }

    return features
