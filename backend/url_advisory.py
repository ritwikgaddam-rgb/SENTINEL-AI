"""URL-structure features and local model observations."""

from functools import lru_cache
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd

try:
    from .assessments import split_url
    from .scoring import model_observation
except ImportError:
    from assessments import split_url
    from scoring import model_observation


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
    except Exception:
        return None


def url_model_observations(urls):
    if not urls:
        return []
    model = candidate()
    if model is None:
        return model_observation(None, urls, 1, "url-context-v1")
    observations = []
    for url in urls:
        parts, host, _ = split_url(url, assume_https=True)
        observations.append(new_features(parts, host))
    return model_observation(model, pd.DataFrame(observations, columns=model.feature_names_in_), 1, "url-context-v1")
