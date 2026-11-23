"""
Sentinel AI - Suspicious Threat Markers Framework
Analyzes URLs and Emails to provide human-readable explainability markers.
Designed to be modular so new markers can be added dynamically.
"""

import re
from urllib.parse import urlsplit
import ipaddress

# Suspicious TLDs frequently used in throwaway phishing sites
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".loan", ".icu"}

# Common targeted brands for spoofing
TARGETED_BRANDS = ["paypal", "netflix", "microsoft", "google", "apple", "amazon", "bank", "chase", "wells fargo", "irs", "support", "secure", "verify"]

# Urgency and panic triggers common in social engineering phishing
URGENCY_PATTERNS = [
    r"\b(urgent|immediately|act now|suspended|suspension|deactivation|terminate|unauthorized|blocked|breach|security alert)\b",
    r"\b(within\s*\d+\s*(hours?|minutes?|days?)|expire|limited time|last chance)\b",
    r"\b(verify your account|confirm your password|update your payment|validate identity)\b",
    r"\b(lottery|winner|inherited|wire transfer|gift card|crypto|bitcoin|payout)\b"
]

def analyze_url_markers(url: str, feature_dict: dict = None) -> list:
    """
    Evaluates a URL against known attack vectors and returns a list of suspicious markers.
    """
    markers = []
    url_lower = url.strip().lower()
    parsed = urlsplit(url)
    domain = parsed.hostname or ""

    # 1. Non-HTTPS marker
    if parsed.scheme != "https":
        markers.append({
            "id": "insecure_http",
            "title": "Unencrypted HTTP Connection",
            "description": "This website does not use modern HTTPS encryption. Traffic and entered credentials can be intercepted.",
            "severity": "high",
            "category": "transport"
        })

    # 2. IP Address in Hostname
    is_ip = False
    try:
        ipaddress.ip_address(domain)
        is_ip = True
    except ValueError:
        pass

    if is_ip or (feature_dict and feature_dict.get("IsDomainIP") == 1):
        markers.append({
            "id": "raw_ip_domain",
            "title": "Raw IP Address Used As Domain",
            "description": "Legitimate platforms use verified domain names. Raw IP addresses are strongly associated with rogue phishing servers.",
            "severity": "danger",
            "category": "infrastructure"
        })

    # 3. Excessive Subdomains (Domain masquerading)
    subdomains = domain.split(".")
    subdomain_count = len(subdomains) - 2 if len(subdomains) > 2 else 0
    if subdomain_count >= 3:
        markers.append({
            "id": "excessive_subdomains",
            "title": "Deep Subdomain Nesting",
            "description": f"Domain contains {subdomain_count} nested subdomains, a technique often used to disguise malicious destinations as legitimate brands.",
            "severity": "medium",
            "category": "domain"
        })

    # 4. Brand Impersonation / Typosquatting in Hostname
    matched_brands = [b for b in TARGETED_BRANDS if b in domain and not domain.endswith(f".{b}.com") and domain != f"{b}.com"]
    if matched_brands:
        markers.append({
            "id": "brand_spoofing_heuristic",
            "title": f"Possible '{matched_brands[0].capitalize()}' Brand Spoofing",
            "description": f"Domain name includes '{matched_brands[0]}' but does not appear to be an official verified domain of that provider.",
            "severity": "high",
            "category": "identity"
        })

    # 5. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            markers.append({
                "id": "suspicious_tld",
                "title": f"High-Risk Top-Level Domain ({tld})",
                "description": f"The top-level domain '{tld}' has statistically high correlation with disposable phishing campaigns.",
                "severity": "medium",
                "category": "domain"
            })
            break

    # 6. Extreme Length or Token Obfuscation
    if len(url) > 120:
        markers.append({
            "id": "abnormal_url_length",
            "title": "Abnormally Long URL Structure",
            "description": f"URL length is {len(url)} characters, often indicating hidden redirects, base64 payloads, or tracking parameters.",
            "severity": "low",
            "category": "structure"
        })

    # 7. Redirection or Credential Harvesting Query Parameters
    if any(param in parsed.query.lower() for param in ["redirect", "dest=", "url=", "continue=", "target=", "login", "auth="]):
        markers.append({
            "id": "open_redirect_potential",
            "title": "Suspicious Redirection / Auth Parameter",
            "description": "URL query parameters suggest an automated redirect or credential relay mechanism.",
            "severity": "medium",
            "category": "behavior"
        })

    # If completely clean
    if not markers:
        markers.append({
            "id": "url_clean_pass",
            "title": "Verified Structure & Secure Transport",
            "description": "No obvious heuristics, rogue IP structures, or brand anomalies were detected on this destination.",
            "severity": "safe",
            "category": "trust"
        })

    return markers


def analyze_email_markers(email_text: str, sender: str = "", links: list = None) -> list:
    """
    Evaluates an email body and metadata for phishing indicators and social engineering tactics.
    """
    markers = []
    text_lower = email_text.lower()

    # 1. Urgency / Pressure Cues
    urgency_matches = []
    for pattern in URGENCY_PATTERNS:
        found = re.findall(pattern, text_lower, flags=re.IGNORECASE)
        if found:
            for item in found:
                val = item if isinstance(item, str) else item[0]
                if val and val not in urgency_matches:
                    urgency_matches.append(val)

    if urgency_matches:
        markers.append({
            "id": "urgency_pressure",
            "title": "High-Pressure Psychological Trigger",
            "description": f"Detected urgency phrasing ('{', '.join(urgency_matches[:3])}'). Attackers create artificial panic to force hasty decisions.",
            "severity": "high",
            "category": "social_engineering"
        })

    # 2. Credential or Financial Demands
    credential_keywords = ["password", "credential", "credit card", "bank details", "cvv", "pin number", "ssn", "aadhaar", "otp"]
    found_creds = [k for k in credential_keywords if k in text_lower]
    if found_creds:
        markers.append({
            "id": "credential_request",
            "title": "Sensitive Information Requested",
            "description": f"Message solicits private credentials ({', '.join(found_creds[:3])}). Legitimate organizations seldom ask for these via email.",
            "severity": "high",
            "category": "harvesting"
        })

    # 3. Suspicious Links inside Email Body
    extracted_urls = links or re.findall(r"https?://[^\s<>\"']+", email_text)
    if extracted_urls:
        ip_links = [u for u in extracted_urls if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u)]
        if ip_links:
            markers.append({
                "id": "embedded_ip_links",
                "title": "Direct IP Links in Message Body",
                "description": f"Contains links pointing directly to numerical IP addresses ({ip_links[0][:35]}...).",
                "severity": "danger",
                "category": "links"
            })
        elif len(extracted_urls) > 5:
            markers.append({
                "id": "excessive_links",
                "title": "High Volume of Embedded Links",
                "description": f"Contains {len(extracted_urls)} outbound links, characteristic of bulk phishing and credential blast attempts.",
                "severity": "medium",
                "category": "links"
            })

    # 4. Sender Spoofing Check (if provided)
    if sender:
        sender_lower = sender.lower()
        for brand in TARGETED_BRANDS:
            if brand in sender_lower and not any(sender_lower.endswith(f"@{brand}.com") or f".{brand}." in sender_lower for brand in [brand]):
                markers.append({
                    "id": "sender_domain_mismatch",
                    "title": f"Sender Address Spoofing Risk ({brand.capitalize()})",
                    "description": f"Sender header displays '{brand}' in display name or domain, but the origin address does not match verified domain records.",
                    "severity": "danger",
                    "category": "sender"
                })
                break

    # 5. Generic Greeting / Salutation
    generic_greetings = ["dear customer", "dear user", "valued customer", "dear member", "undisclosed-recipients"]
    if any(g in text_lower[:200] for g in generic_greetings):
        markers.append({
            "id": "generic_greeting",
            "title": "Impersonal Salutation",
            "description": "Message uses a generic salutation instead of addressing you by name, standard in broad phishing campaigns.",
            "severity": "low",
            "category": "social_engineering"
        })

    if not markers:
        markers.append({
            "id": "email_clean_pass",
            "title": "No Direct Phishing Flags Found",
            "description": "No urgent social engineering patterns, direct credential demands, or rogue embedded links were detected.",
            "severity": "safe",
            "category": "trust"
        })

    return markers
