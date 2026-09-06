import pandas as pd
import joblib

feature_columns = joblib.load("models/feature_columns.pkl")
scaler = joblib.load("models/scaler.pkl")

def extract_features(packet):
    df = pd.DataFrame([packet])
    df = df.fillna(0)

    categorical_cols = df.select_dtypes(include=["object"]).columns
    if len(categorical_cols) > 0:
        df = pd.get_dummies(df, columns=categorical_cols)

    df = df.reindex(columns=feature_columns, fill_value=0)

    features_scaled = scaler.transform(df)

    return pd.DataFrame(features_scaled, columns=feature_columns)
