import joblib
import pandas as pd

model, features = joblib.load("ml/model.pkl")

def predict_log(log):
    try:
        df = pd.DataFrame([log])
        df = df.reindex(columns=features, fill_value=0)

        score = model.decision_function(df)[0]
        prediction = model.predict(df)[0]

        if prediction == -1:
            label = "ANOMALY"
        else:
            label = "NORMAL"

        return label, score

    except Exception as e:
        print("AI error:", e)
        return None, None
