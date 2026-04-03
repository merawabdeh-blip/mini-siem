import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

print("Loading dataset...")

df1 = pd.read_csv("dataset/UNSW-NB15_1.csv", header=None, nrows=50000)
df2 = pd.read_csv("dataset/UNSW-NB15_2.csv", header=None, nrows=50000)

df = pd.concat([df1, df2])

print("Dataset loaded:", df.shape)

# 🔥 تحويل لكل القيم الرقمية
df = df.apply(pd.to_numeric, errors='coerce')

# حذف الأعمدة اللي كلها NaN
df = df.dropna(axis=1)

# حذف الصفوف اللي فيها NaN
df = df.dropna()

features = df.columns.tolist()

print("After cleaning:", df.shape)

model = IsolationForest(contamination=0.05)
model.fit(df)

joblib.dump((model, features), "ml/model.pkl")

print("Model trained & saved!")
