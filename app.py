from flask import Flask, render_template, request
import joblib
import pandas as pd
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Load trained model
model = joblib.load("phishing_detector.pkl")

app = Flask(__name__)

# Function to extract features from URL
def extract_features(url):
    try:
        # Parse URL
        parsed_url = urlparse(url)

        # Length of full URL
        length_url = len(url)

        # Length of hostname (domain only)
        length_hostname = len(parsed_url.netloc)

        # Number of dots in hostname
        nb_dots = parsed_url.netloc.count(".")

        # HTTPS token (1 if https, else 0)
        https_token = 1 if parsed_url.scheme == "https" else 0

        # Number of hyperlinks in webpage
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            nb_hyperlinks = len(soup.find_all("a"))
        except:
            nb_hyperlinks = 0  # fallback if website can't be loaded

        # Return as dataframe row
        return pd.DataFrame([[
            length_url, length_hostname, nb_dots, https_token, nb_hyperlinks
        ]], columns=["length_url", "length_hostname", "nb_dots", "https_token", "nb_hyperlinks"])

    except Exception as e:
        print("Error extracting features:", e)
        return None

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    if request.method == "POST":
        url = request.form["url"]

        # Extract features
        features = extract_features(url)

        if features is not None:
            # Predict with model
            prediction = model.predict(features)[0]
            result = "Phishing Website ❌" if prediction == 1 else "Legitimate Website ✅"
        else:
            result = "Error extracting features from the URL."

        return render_template("index.html", prediction=result, input_url=url)

if __name__ == "__main__":
    app.run(debug=True)
