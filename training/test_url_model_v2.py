import argparse
from pathlib import Path

import joblib
from url_features import extract_url_features

urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.microsoft.com",
    "http://192.168.1.1/login",
    "https://account-verify.example.com/login",
    "https://secure-login.example.org/update"
]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check the archived URL model on example URLs.")
    parser.add_argument("--legacy-models", required=True, type=Path)
    directory = parser.parse_args().legacy_models
    model = joblib.load(directory / "url_phishing_model_v2.joblib")
    columns = joblib.load(directory / "url_features_v2.joblib")
    phishing_index = list(model.classes_).index(0)
    for url in urls:
        features = extract_url_features(url)[columns]
        prediction = model.predict(features)[0]
        probabilities = model.predict_proba(features)[0]
        print("URL:", url)
        print("Prediction: Phishing" if prediction == 0 else "Prediction: Legitimate")
        print("Phishing probability:", round(probabilities[phishing_index] * 100, 2), "%")
        print()
