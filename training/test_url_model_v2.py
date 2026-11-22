import joblib
from url_features import extract_url_features

model = joblib.load("models/url_phishing_model_v2.joblib")
columns = joblib.load("models/url_features_v2.joblib")


urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.microsoft.com",
    "http://192.168.1.1/login",
    "https://account-verify.example.com/login",
    "https://secure-login.example.org/update"
]

for url in urls:
    features = extract_url_features(url)
    features = features[columns]

    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]

    print("URL:", url)

    if prediction == 0:
        print("Prediction: Phishing")
    else:
        print("Prediction: Legitimate")

    phishing_index = list(model.classes_).index(0)
    print("Phishing probability:", round(probabilities[phishing_index] * 100, 2), "%")
    print()