import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler


def preprocess_data(data, training=True):

    data = data.copy()

    # Remove duplicates
    data = data.drop_duplicates()

    # Replace "-" with NaN
    data = data.replace("-", np.nan)

    # Drop columns that are not useful
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
        "weird_notice"
    ]

    data = data.drop(columns=drop_cols, errors="ignore")

    # Fill missing values
    data = data.fillna(0)

    # Separate label if present
    if "label" in data.columns:
        y = data["label"]
        X = data.drop("label", axis=1)
    else:
        y = None
        X = data

    # Encode categorical features
    categorical_cols = X.select_dtypes(include=["object"]).columns
    X = pd.get_dummies(X, columns=categorical_cols)

    # Ensure numeric types only
    X = X.apply(pd.to_numeric, errors="coerce")

    # Replace NaN again if conversion created some
    X = X.fillna(0)

    # ---------------------------
    # TRAINING MODE
    # ---------------------------
    if training:

        # Save feature columns
        joblib.dump(X.columns, "models/feature_columns.pkl")

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Save scaler
        joblib.dump(scaler, "models/scaler.pkl")

    # ---------------------------
    # INFERENCE MODE
    # ---------------------------
    else:

        saved_columns = joblib.load("models/feature_columns.pkl")

        # Align columns
        X = X.reindex(columns=saved_columns, fill_value=0)

        scaler = joblib.load("models/scaler.pkl")

        X_scaled = scaler.transform(X)

    X = pd.DataFrame(X_scaled, columns=X.columns)

    return X, y