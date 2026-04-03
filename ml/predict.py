import pandas as pd
import joblib

# تحميل المودل + الفيتشرز
model, features = joblib.load("ml/model.pkl")

def predict_log(log):

    # نحول الداتا لـ DataFrame
    df = pd.DataFrame([log])

    # 🔥 نضمن نفس الأعمدة ونفس الترتيب
    df = df.reindex(columns=features, fill_value=0)

    # prediction
    score = model.decision_function(df)[0]

    print("Score:", score)

    if score < -0.1:
        return "ATTACK"
    return "NORMAL"


# تجربة
sample_log = {col: 0 for col in features}

print("Prediction:", predict_log(sample_log))
