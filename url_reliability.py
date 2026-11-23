"""Offline URL assessment with an explicit inconclusive outcome."""

from urllib.parse import urlsplit

import pandas as pd

from url_features import url_feature_values


PHISHING_LABEL = 0
# Thresholds selected on the domain-disjoint validation split. See training/URL_EVALUATION.md.
LEGITIMATE_AT_MOST = 0.25
PHISHING_AT_LEAST = 0.85


def url_model_values(url):
    parsed = urlsplit(url)
    path = "" if parsed.path == "/" else parsed.path
    # Equivalent root spellings receive the same score. Query and fragment text
    # are excluded because the training sources overrepresent them in phishing.
    model_url = parsed._replace(path=path, query="", fragment="").geturl()
    return url_feature_values(model_url)


def analyze_url(model, url, feature_order=None):
    url = url.strip()
    parsed = urlsplit(url)
    features = url_feature_values(url)
    hostname_is_ip = bool(features["IsDomainIP"])
    columns = model.feature_names_in_ if feature_order is None else feature_order
    model_input = pd.DataFrame([url_model_values(url)], columns=columns)
    phishing_index = list(model.classes_).index(PHISHING_LABEL)
    score = float(model.predict_proba(model_input)[0, phishing_index])

    reason = None
    if score >= PHISHING_AT_LEAST:
        prediction, risk = "Phishing", "High"
    elif score <= LEGITIMATE_AT_MOST:
        prediction, risk = "Legitimate", "Low"
    else:
        prediction, risk = "Insufficient information", "Unrated"
        reason = "The URL structure does not support a confident verdict."
        score = None

    return {
        "prediction": prediction,
        "risk_level": risk,
        "phishing_probability": score,
        "reason": reason,
        "features": features,
        "url_analysis": {
            "observations": {
                "uses_https": bool(features["IsHTTPS"]),
                "url_length": features["URLLength"],
                "hostname_length": features["DomainLength"],
                "subdomain_count_estimate": 0 if hostname_is_ip else features["NoOfSubDomain"],
                "hostname_is_ip_address": hostname_is_ip,
                "query_field_count": sum(bool(field) for field in parsed.query.split("&")),
            },
            "limitations": "URL structure only. Page content and ownership are unverified.",
        },
    }
