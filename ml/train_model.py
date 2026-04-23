import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

BASE_DIR = os.path.expanduser("~/mini-siem/dataset")
TRAIN_FILES = [
    "UNSW-NB15_1.csv",
    "UNSW-NB15_2.csv",
    "UNSW-NB15_3.csv",
]

MODEL_PATH = "ml/model.pkl"
ENCODERS_PATH = "ml/encoders.pkl"


def load_unsw_files(file_list):
    frames = []
    for name in file_list:
        path = os.path.join(BASE_DIR, name)
        df = pd.read_csv(path, header=None)
        frames.append(df)
        print(f"Loaded {name}: {df.shape}")
    return pd.concat(frames, ignore_index=True)


def preprocess_unsw(df, fit_encoders=True, encoders=None):
    df = df.copy()

    label_col = 48
    y = df[label_col].copy()
    X = df.drop(columns=[label_col])

    # نخزن أسماء الأعمدة
    feature_columns = X.columns.tolist()

    # أعمدة object نحولها لأرقام
    if fit_encoders:
        encoders = {}

    object_cols = X.select_dtypes(include=["object"]).columns.tolist()

    for col in object_cols:
        X[col] = X[col].astype(str).fillna("missing")

        if fit_encoders:
            uniques = sorted(X[col].unique().tolist())
            mapping = {val: idx for idx, val in enumerate(uniques)}
            encoders[col] = mapping

        mapping = encoders.get(col, {})
        X[col] = X[col].map(lambda v: mapping.get(v, -1))

    # باقي الأعمدة نخليها رقمية
    X = X.apply(pd.to_numeric, errors="coerce")

    # نعوض القيم الفارغة بوسيط العمود
    medians = X.median(numeric_only=True)
    X = X.fillna(medians)

    return X, y, feature_columns, encoders, medians.to_dict()


def main():
    print("Loading UNSW training files...")
    df_train = load_unsw_files(TRAIN_FILES)

    print("Preprocessing training data...")
    X_all, y_all, feature_columns, encoders, medians = preprocess_unsw(df_train, fit_encoders=True)

    # تدريب Isolation Forest فقط على الطبيعي
    normal_mask = (y_all == 0)
    X_train_normal = X_all[normal_mask]

    print("All training rows:", len(X_all))
    print("Normal training rows:", len(X_train_normal))
    print("Attack rows excluded from training:", int((y_all == 1).sum()))

    model = IsolationForest(
        n_estimators=300,
        contamination=0.10,
        random_state=42
    )
    model.fit(X_train_normal)

    joblib.dump((model, feature_columns, medians), MODEL_PATH)
    joblib.dump(encoders, ENCODERS_PATH)

    print("Model trained and saved successfully!")
    print("Model path:", MODEL_PATH)
    print("Encoders path:", ENCODERS_PATH)


if __name__ == "__main__":
    main()
