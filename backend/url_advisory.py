"""Advisory URL-structure classification. The result never sets the verdict."""

from functools import lru_cache
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd

try:
    from .assessments import split_url
except ImportError:
    from assessments import split_url


def extract_features_dict(url: str) -> dict:
    """Extracts URL numerical and structural features without hard dependency on pandas."""
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlsplit(url)
    domain = parsed.hostname or ""

    is_ip = 0
    try:
        ipaddress.ip_address(domain)
        is_ip = 1
    except ValueError:
        pass

    letters = sum(1 for c in url if c.isalpha())
    digits = sum(1 for c in url if c.isdigit())
    subdomains = max(0, len(domain.split(".")) - 2)
    is_https = 1 if parsed.scheme == "https" else 0

    return {
        "URLLength": len(url),
        "DomainLength": len(domain),
        "IsDomainIP": is_ip,
        "NoOfSubDomain": subdomains,
        "NoOfLettersInURL": letters,
        "NoOfDegitsInURL": digits,
        "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "IsHTTPS": is_https
    }


def new_features(parts, host):
    path = "" if parts.path == "/" else parts.path
    columns = extract_features_dict(f"{parts.scheme}://{host}{path}")
    return {key: value for key, value in columns.items() if key not in {"NoOfQMarkInURL", "NoOfAmpersandInURL"}} | {
        "path_length": len(path), "path_segments": sum(bool(item) for item in path.split("/")),
        "hyphens_in_hostname": host.count("-"),
        "internationalized": int(any(label.startswith("xn--") for label in host.split("."))),
        "percent_encoded_path": path.count("%"),
    }


@lru_cache(maxsize=1)
def candidate():
    path = Path(__file__).resolve().parents[1] / "models/url_context_candidate.joblib"
    if not path.exists():
        return None
    try:
        model = joblib.load(path)
        return model if set(model.classes_) == {0, 1} else None
    except (OSError, ValueError, ImportError, AttributeError):
        return None


def url_model_observations(urls):
    if not urls:
        return []
    unavailable = {"status": "unavailable", "message": "The experimental URL model is unavailable."}
    model = candidate()
    if model is None:
        return [unavailable for _ in urls]
    observations = []
    for url in urls:
        parts, host, _ = split_url(url, assume_https=True)
        observations.append(new_features(parts, host))
    try:
        predictions = model.predict(pd.DataFrame(observations, columns=model.feature_names_in_))
    except (AttributeError, ValueError, TypeError):
        return [unavailable for _ in urls]
    return [
        {"status": "flagged", "message": "The experimental structure model flagged this address for review."}
        if prediction == 1 else
        {"status": "not_flagged", "message": "The experimental structure model did not flag this address."}
        for prediction in predictions
    ]
