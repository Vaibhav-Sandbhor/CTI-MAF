import numpy as np

def build_sequences(df, seq_len=10):
    X, y = [], []
    features = df.drop(columns=["label"]).values
    labels = df["label"].values

    for i in range(len(features) - seq_len):
        X.append(features[i:i+seq_len])
        y.append(labels[i+seq_len])

    return np.array(X), np.array(y)
