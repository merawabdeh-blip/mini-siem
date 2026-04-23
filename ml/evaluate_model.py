import os
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

BASE_DIR = os.path.expanduser("~/mini-siem/dataset")
TEST_FILE = "UNSW-NB15_4.csv"

MODEL_PATH = "ml/model.pkl"
ENCODERS_PATH = "ml/encoders.pkl"


def preprocess_test(df, feature_columns, encoders, medians):
    df = df.copy()

    label_col = 48
    y = df[label_col].copy()
    X = df.drop(columns=[label_col])

    # نفس أعمدة التدريب
    X = X[feature_columns]

    object_cols = X.select_dtypes(include=["object"]).columns.tolist()

    for col in object_cols:
        X[col] = X[col].astype(str).fillna("missing")
        mapping = encoders.get(col, {})
        X[col] = X[col].map(lambda v: mapping.get(v, -1))

    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.fillna(pd.Series(medians))

    return X, y


def main():
    model, feature_columns, medians = joblib.load(MODEL_PATH)
    encoders = joblib.load(ENCODERS_PATH)

    path = os.path.join(BASE_DIR, TEST_FILE)
    df_test = pd.read_csv(path, header=None)
    print(f"Loaded test file: {TEST_FILE} -> {df_test.shape}")

    X_test, y_true = preprocess_test(df_test, feature_columns, encoders, medians)

    raw_pred = model.predict(X_test)
    # Isolation Forest: -1 anomaly, 1 normal
    y_pred = pd.Series(raw_pred).map({1: 0, -1: 1})  # نخلي 1 = attack

    scores = model.decision_function(X_test)

    print("\n=== Evaluation Results ===")
    print("Accuracy:", accuracy_score(y_true, y_pred))
    print("Precision:", precision_score(y_true, y_pred, zero_division=0))
    print("Recall:", recall_score(y_true, y_pred, zero_division=0))
    print("F1 Score:", f1_score(y_true, y_pred, zero_division=0))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_true, y_pred))

    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, zero_division=0))

    print("\nScore Summary:")
    print("Min score:", scores.min())
    print("Max score:", scores.max())
    print("Mean score:", scores.mean())

    print("\nPrediction Counts:")
    print(pd.Series(y_pred).value_counts().sort_index().rename(index={0: "NORMAL", 1: "ATTACK"}))


if __name__ == "__main__":
    main()
