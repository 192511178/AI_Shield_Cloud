import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

from xgboost import XGBClassifier

# Load Dataset

df = pd.read_csv("ddos_dataset.csv")

# Convert Protocol

encoder = LabelEncoder()

df["Protocol"] = encoder.fit_transform(
    df["Protocol"]
)

# Features

X = df[
    [
        "Requests",
        "Protocol"
    ]
]

# Target

y = df["Attack"]

# Train Test Split

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Model

model = XGBClassifier()

model.fit(
    X_train,
    y_train
)

# Accuracy

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print(
    "Accuracy:",
    round(
        accuracy * 100,
        2
    ),
    "%"
)

# Save Model

joblib.dump(
    model,
    "xgboost_model.pkl"
)

joblib.dump(
    encoder,
    "protocol_encoder.pkl"
)

print("Model Saved Successfully")