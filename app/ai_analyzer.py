from sklearn.ensemble import IsolationForest
import numpy as np

def analyze_logs(logs):

    data = []

    for log in logs:
        data.append([len(log.message)])

    model = IsolationForest(contamination=0.1)

    model.fit(data)

    predictions = model.predict(data)

    return predictions
