import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import matplotlib.pyplot as plt
import numpy as np
import joblib

# Load dataset
data = pd.read_csv("dataset_phishing.csv")

# Features & target# Use only 5 features for Flask app
X = data[["length_url", "length_hostname", "nb_dots", "https_token", "nb_hyperlinks"]]
y = data["status"].replace({-1: 0, 1: 1})

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Train model
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("✅ Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "phishing_detector.pkl")
print("Model saved as phishing_detector.pkl")
