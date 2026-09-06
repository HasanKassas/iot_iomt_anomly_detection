import json
import os
from typing import Dict, Tuple

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import tensorflow as tf
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


def _ensure_results_dir() -> str:
    os.makedirs("results", exist_ok=True)
    return "results"


def _prepare_xy(df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray]:
    df = df.copy()
    df = df.drop_duplicates()
    df = df.replace("-", np.nan).fillna(0)

    if "label" not in df.columns:
        raise ValueError("dataset must include a 'label' column (0/1)")

    y = df["label"].astype(int).to_numpy()

    drop_cols = [
        "src_ip",
        "dst_ip",
        "type",
        "dns_query",
        "host",
        "server_name",
        "http_host",
        "http_user_agent",
        "http_orig_mime_types",
        "http_resp_mime_types",
        "weird_name",
        "weird_addl",
        "weird_notice",
    ]
    X = df.drop(columns=["label"], errors="ignore")
    X = X.drop(columns=drop_cols, errors="ignore")

    categorical_cols = X.select_dtypes(include=["object"]).columns
    X = pd.get_dummies(X, columns=categorical_cols)
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

    cols = None
    if os.path.isfile("models/feature_columns.pkl"):
        try:
            cols = list(joblib.load("models/feature_columns.pkl"))
        except Exception:
            cols = None
    if cols:
        X = X.reindex(columns=cols, fill_value=0)

    return X, y


def _plot_class_distribution(y: np.ndarray, out_path: str) -> None:
    y = np.asarray(y).reshape(-1)
    labels, counts = np.unique(y, return_counts=True)
    counts_map = {int(l): int(c) for l, c in zip(labels, counts)}
    normal = int(counts_map.get(0, 0))
    attack = int(counts_map.get(1, 0))

    plt.figure(figsize=(6, 4))
    sns.barplot(x=["Normal (0)", "Attack (1)"], y=[normal, attack])
    plt.title("Class Distribution")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def _plot_confusion_matrix(cm: np.ndarray, title: str, out_path: str) -> None:
    plt.figure(figsize=(5.5, 4.5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
    plt.title(title)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def _calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    return {
        "Accuracy": float(accuracy_score(y_true, y_pred)),
        "Precision": float(report.get("1", {}).get("precision", 0.0)),
        "Recall": float(report.get("1", {}).get("recall", 0.0)),
        "F1-Score": float(report.get("1", {}).get("f1-score", 0.0)),
        "FPR": float(fpr),
    }


def evaluate_all(X_df: pd.DataFrame, y: np.ndarray) -> Dict[str, Dict[str, float]]:
    results_dir = _ensure_results_dir()

    _plot_class_distribution(y, os.path.join(results_dir, "class_distribution.png"))

    results: Dict[str, Dict[str, float]] = {}

    # Random Forest (current)
    rf_model = joblib.load("models/anomaly_model.pkl")
    rf_scaler = joblib.load("models/scaler.pkl") if os.path.isfile("models/scaler.pkl") else None
    X_rf = X_df.to_numpy(dtype=np.float32)
    if rf_scaler is not None:
        try:
            X_rf = rf_scaler.transform(X_rf)
        except Exception:
            pass
    rf_pred = np.asarray(rf_model.predict(X_rf), dtype=int).reshape(-1)
    results["Random Forest"] = _calculate_metrics(y, rf_pred)
    _plot_confusion_matrix(confusion_matrix(y, rf_pred, labels=[0, 1]), "Confusion Matrix — Random Forest", os.path.join(results_dir, "confusion_matrix_rf.png"))

    # Autoencoder (current)
    ae_model = tf.keras.models.load_model("models/autoencoder_optimized.keras")
    ae_scaler = joblib.load("models/autoencoder_scaler.pkl") if os.path.isfile("models/autoencoder_scaler.pkl") else None

    threshold = 0.0
    if os.path.isfile("models/autoencoder_threshold.json"):
        try:
            with open("models/autoencoder_threshold.json", "r", encoding="utf-8") as f:
                payload = json.load(f) or {}
            threshold = float(payload.get("threshold", 0.0) or 0.0)
            cand = payload.get("candidates") or {}
            pct = cand.get("percentile") if isinstance(cand, dict) else None
            if isinstance(pct, dict):
                p99 = float(pct.get("threshold", 0.0) or 0.0)
                if p99 > 0:
                    threshold = p99
        except Exception:
            threshold = 0.0

    X_ae = X_df.to_numpy(dtype=np.float32)
    if ae_scaler is not None:
        try:
            X_ae = ae_scaler.transform(X_ae)
        except Exception:
            pass

    recon = ae_model.predict(X_ae, verbose=0)
    mse = np.mean(np.square(X_ae - recon), axis=1)
    ae_pred = (mse > float(threshold)).astype(int)
    results["Autoencoder"] = _calculate_metrics(y, ae_pred)
    _plot_confusion_matrix(confusion_matrix(y, ae_pred, labels=[0, 1]), "Confusion Matrix — Autoencoder", os.path.join(results_dir, "confusion_matrix_ae.png"))

    comparison_df = pd.DataFrame.from_dict(results, orient="index")
    comparison_df.index.name = "Model"
    comparison_df.to_csv(os.path.join(results_dir, "model_comparison.csv"))

    return results


if __name__ == "__main__":
    from src.load_data import load_data

    print("\n" + "=" * 30)
    print("MODEL EVALUATION (CLEAN)")
    print("=" * 30)

    df = load_data("data/train_test_network.csv")
    X_df, y = _prepare_xy(df)
    out = evaluate_all(X_df, y)
    for k, v in out.items():
        print(f"{k}: {v}")
