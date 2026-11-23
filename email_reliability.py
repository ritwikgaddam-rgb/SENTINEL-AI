"""Score email text using the saved binary TF-IDF pipeline and its evidence policy."""

import numpy as np


INSUFFICIENT_INFORMATION = "Insufficient information"
# Selected and checked on the separate corpora in training/evaluate_email.py.
MIN_EFFECTIVE_FEATURES = 4.5


def effective_feature_count(row):
    """Count equally weighted features that would have the observed concentration."""
    squared_weights = np.square(row.data)
    total = squared_weights.sum()
    return float(total**2 / np.square(squared_weights).sum()) if total else 0.0


def email_scores(model, feature_rows):
    classifier = model.named_steps["classifier"]
    phishing_index = classifier.classes_.tolist().index(1)
    return classifier.predict_proba(feature_rows)[:, phishing_index]


def assess_email(model, text, *, feature_row=None):
    if feature_row is None:
        feature_row = model.named_steps["tfidf"].transform([text])
    support = effective_feature_count(feature_row)
    evidence = {"effective_features": support, "minimum_effective_features": MIN_EFFECTIVE_FEATURES}
    if support < MIN_EFFECTIVE_FEATURES:
        return {
            "prediction": INSUFFICIENT_INFORMATION,
            "risk_level": "Unrated",
            "phishing_probability": None,
            "reason": "The model recognized too little distinct evidence to assess this text reliably.",
            "evidence_policy": evidence,
        }

    probability = float(email_scores(model, feature_row)[0])
    is_phishing = probability > 0.5
    return {
        "prediction": "Phishing" if is_phishing else "Legitimate",
        "risk_level": "High" if is_phishing else "Low",
        "phishing_probability": probability,
        "evidence_policy": evidence,
    }
