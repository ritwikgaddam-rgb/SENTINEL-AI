"""Offline evidence for email, URL and webpage scans."""

import ipaddress
import json
import os
import re
import unicodedata
from email.utils import parseaddr
from urllib.parse import parse_qsl, unquote, urlsplit

from bs4 import BeautifulSoup
import requests
import tldextract
from privacy_detector import find_findings


PUBLIC_SUFFIX = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)
LINK = re.compile(r"https?://[^\s<>\"']+", re.I)
MAX_LINKS = 40

CREDENTIAL_REQUEST = re.compile(
    r"\b(?:send|share|reply with|provide|submit|enter|confirm|give)\s+(?:(?:me|us)\s+)?"
    r"(?:(?:your|the)\s+)?(?:(?:current|full|account)\s+)?"
    r"(?:password|passphrase|(?:one[- ]time|verification|security) code|OTP|CVV|"
    r"credit card number|bank details|Aadhaar number|social security number)\b"
    r"(?!\s+(?:reset|change|update|policy)\b)", re.I
)
PRESSURE = re.compile(r"\b(?:act now|respond immediately|final (?:notice|warning)|"
                      r"within \d{1,3} (?:hours?|minutes?)|(?:account|access) (?:will be|has been) "
                      r"(?:suspended|disabled|locked))\b", re.I)
PAYMENT = re.compile(r"\b(?:send|wire|transfer|pay|purchase|buy)\s+(?:(?:the|your|some|a)\s+)?"
                     r"(?:money|funds|payment|gift cards?|bitcoin|crypto)\b", re.I)
ACTION = re.compile(r"\b(?:click|open|follow|visit|sign in|log in|verify|confirm|update)\b", re.I)
VERIFY = re.compile(r"\b(?:verify (?:your )?(?:account|identity)|sign in|log in|confirm your identity)\b", re.I)
NEGATION = re.compile(r"\b(?:never|do not|don't|will not|won't)\b[^.!?\n]{0,36}$", re.I)
SECURITY_NOTICE = re.compile(r"\b(?:security alert|unusual activity|new sign[- ]in|account restriction)\b", re.I)
QUOTED_LINES = re.compile(r"(?m)^[ \t]*>[^\n]+")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly"}
BRANDS = {"PayPal": "paypal.com", "Amazon": "amazon.com", "Google": "google.com",
          "Apple": "apple.com", "Microsoft": "microsoft.com", "Netflix": "netflix.com"}
LOOKALIKES = str.maketrans("0135аекморстхуі", "olesaekmopctxyi")


def marker(code, title, description, severity="medium", category="context", **extra):
    return {"id": code, "title": title, "description": description,
            "severity": severity, "category": category, **extra}


def outcome(markers, flagged, enough=True):
    if flagged:
        return "suspicious", "Suspicious", "The provided material contains specific warning signs. Verify through a separate trusted channel."
    if not enough or markers:
        return "uncertain", "Insufficient information", "The available evidence does not establish a phishing verdict."
    return "neutral", "No clear phishing indicators detected", "No clear indicators were found in the material checked. Verify unexpected requests independently."


def split_url(value, assume_https=False):
    if not isinstance(value, str) or len(value) > 2083:
        raise ValueError("Enter an HTTP or HTTPS URL.")
    value = value.strip()
    if assume_https and "://" not in value:
        value = "https://" + value
    if any(char.isspace() or ord(char) < 32 or char == "\\" for char in value):
        raise ValueError("Enter an HTTP or HTTPS URL.")
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Enter an HTTP or HTTPS URL.")
    parts.port  # Reject malformed ports.
    host = parts.hostname.rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
        host = host.encode("idna").decode("ascii")
        if (not re.fullmatch(r"(?=.{1,253}$)[a-z0-9-]+(?:\.[a-z0-9-]+)*", host)
                or any(len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split("."))):
            raise ValueError("Enter an HTTP or HTTPS URL.")
    return parts, host, ip


def registrable(host):
    host = host.rstrip(".").lower()
    external = PUBLIC_SUFFIX(host)
    return f"{external.domain}.{external.suffix}" if external.suffix else host


def destination(parts, host):
    """Keep the host and path of an input URL while removing credentials and query data."""
    authority = f"[{host}]" if ":" in host else host
    if parts.port is not None:
        authority += f":{parts.port}"
    return f"{parts.scheme}://{authority}{parts.path or '/'}"


def lookalike_brand(host):
    label = PUBLIC_SUFFIX(host).domain
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except UnicodeError:
            return False
    skeleton = unicodedata.normalize("NFKC", label).casefold().translate(LOOKALIKES)
    return skeleton != label and skeleton in {name.lower() for name in BRANDS}


def url_evidence(value):
    parts, host, ip = split_url(value, assume_https=True)
    markers = []
    if parts.scheme != "https":
        markers.append(marker("insecure_http", "Unencrypted HTTP", "The address uses HTTP. Transport encryption is separate from trust.", category="transport"))
    if ip is not None:
        markers.append(marker("raw_ip_domain", "IP address destination", "The destination is an IP address rather than a domain.", category="destination"))
    if parts.username is not None:
        markers.append(marker("embedded_userinfo", "User information before hostname",
                              "The address includes user information before the actual hostname.", "high", "destination"))
    if host in SHORTENERS:
        markers.append(marker("shortener", "Shortened link", "The final destination is not visible from the address.", category="destination"))
    if any(name.startswith("xn--") for name in host.split(".")):
        markers.append(marker("internationalized_domain", "Internationalized domain", "Check the spelling of the actual hostname.", category="destination"))
    if lookalike_brand(host):
        markers.append(marker("lookalike_domain", "Possible brand lookalike",
                              "The domain uses characters that resemble a known brand name.", category="destination"))
    keys = {key.casefold() for key, _ in parse_qsl(parts.query, max_num_fields=100, errors="replace")} if parts.query.count("&") < 100 else set()
    if keys & {"redirect", "redirect_uri", "return_url", "returnto", "continue", "target", "dest", "url"}:
        markers.append(marker("destination_parameter", "Destination parameter", "A query field can describe another destination. Redirects were not followed.", category="structure"))
    if len(unquote(parts.path)) > 100 or parts.path.count("%") > 6:
        markers.append(marker("complex_path", "Complex URL path", "The path is long or has several encoded characters.", "low", "structure"))
    external = PUBLIC_SUFFIX(host)
    if ip is None and external.subdomain.count(".") >= 2:
        markers.append(marker("deep_subdomains", "Nested subdomains", "Inspect the registrable domain rather than the leading labels.", "low", "destination"))
    brand = next((brand for brand, domain in BRANDS.items()
                  if brand.casefold() in host.split(".")[:-2] and registrable(host) != domain), None)
    if brand:
        markers.append(marker("brand_in_subdomain", "Brand wording in a subdomain",
                              "The named brand appears before a different registrable domain.", category="destination"))
    # User-information tricks and exact hostname differences are stronger than HTTPS or generic words.
    level, assessment, explanation = outcome(markers, parts.username is not None, enough=False)
    return {"url": destination(parts, host), "hostname": host, "registrable_domain": registrable(host), "scheme": parts.scheme,
            "risk_level": level, "assessment": assessment, "explanation": explanation, "markers": markers,
            "risk_score": None, "safety_score": None, "ml_evaluated": False}


def link_items(text, html, supplied):
    anchors = []
    limited = False
    visible = text
    if html:
        document = BeautifulSoup(html, "html.parser")
        for tag in document(["script", "style", "head", "noscript", "template", "iframe"]):
            tag.decompose()
        html_links = document.select("a[href]", limit=MAX_LINKS + 1)
        limited = len(html_links) > MAX_LINKS
        anchors.extend((a["href"], a.get_text(" ", strip=True)[:200]) for a in html_links)
        if not visible:
            visible = document.get_text(" ", strip=True)[:20000]
    anchors.extend((item, "") if isinstance(item, str) else (item.get("url"), item.get("label", ""))
                   for item in supplied if isinstance(item, (str, dict)))
    anchors.extend((match.group().rstrip(".,;!?)"), "") for match in LINK.finditer(visible))
    links = {}
    for value, label in anchors:
        try:
            parts, host, _ = split_url(value)
        except (ValueError, UnicodeError):
            continue
        key = (parts.scheme, host, parts.port, parts.path or "/", parts.query, parts.username is not None)
        if key not in links and len(links) >= MAX_LINKS:
            limited = True
            continue
        if key not in links:
            links[key] = {"url": value, "display_text": "", "hostname": host}
        if isinstance(label, str) and label:
            displayed = LINK.search(label) or re.fullmatch(r"(?:[\w-]+\.)+[a-z]{2,}(?:/\S*)?", label.strip(), re.I)
            try:
                displayed_host = split_url(displayed.group().rstrip(".,;!?)"), assume_https=True)[1] if displayed else ""
            except (ValueError, UnicodeError):
                displayed_host = ""
            if not links[key]["display_text"] or (displayed_host and registrable(displayed_host) != registrable(host)):
                links[key]["display_text"] = label[:200]
                links[key]["displayed_hostname"] = displayed_host
    return visible, list(links.values()), limited


def writing_checks(text):
    prose = LINK.sub(lambda match: " " * len(match.group()), text)
    prose = re.sub(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", lambda match: " " * len(match.group()), prose)
    prose = re.sub(r"```[\s\S]*?```|(?m:^--\s*$[\s\S]*)", lambda match: " " * len(match.group()), prose)
    prose = QUOTED_LINES.sub(lambda match: " " * len(match.group()), prose)
    words = len(re.findall(r"\b\w+\b", prose))
    port = os.getenv("SENTINELAI_LANGUAGETOOL_PORT")
    if port and port.isascii() and port.isdecimal() and len(port) <= 5 and 1 <= int(port) <= 65535:
        try:
            # Preserve both Python and UTF-16 character offsets for the issues
            # the writing service returns.
            characters = list(prose)
            for hit in find_findings(prose):
                characters[hit.start:hit.end] = ("🟠" if ord(c) > 0xFFFF else " " for c in prose[hit.start:hit.end])
            prose = "".join(characters)
            findings = local_language_tool(prose, text, int(port))
            return writing_result("local_languagetool", words, findings)
        except (requests.RequestException, ValueError, TypeError, KeyError, AttributeError):
            pass
    rules = (
        (r"\b(?:recieve|teh|definately|seperate)\b", "Possible spelling error", {"recieve": "receive", "teh": "the", "definately": "definitely", "seperate": "separate"}),
        (r"\b(?:your account|the account|it)\s+(?P<issue>have)(?=\s+been\b)", "Subject–verb agreement", {"have": "has"}),
        (r"\b(?:I|you|we|they)\s+(?P<issue>has)(?=\s+[a-z]+(?:ed|en)\b)",
         "Subject–verb agreement", {"has": "have"}),
        (r"\b(?P<word>[A-Za-z]{2,})[ \t]+(?P<issue>(?P=word))\b", "Repeated word", {}),
        (r"[!?]{3,}", "Repeated punctuation", {}),
        (r"\b[A-Z]{4,}(?:[ \t]+[A-Z]{4,}){2,}\b", "Several consecutive words in capitals", {}),
    )
    findings = []
    for pattern, label, suggestions in rules:
        for match in re.finditer(pattern, prose, flags=0 if "capitals" in label else re.I | re.ASCII):
            start, end = match.span("issue") if "issue" in match.groupdict() else match.span()
            findings.append({"description": label, "excerpt": text[start:end][:100], "start": start,
                             "suggestion": suggestions.get(text[start:end].lower())})
    return writing_result("limited_local_english", words, findings)


def writing_result(status, words, findings):
    unique = {(item["start"], item["description"]): item for item in findings}
    findings = sorted(unique.values(), key=lambda item: item["start"])
    return {"status": status, "count": len(findings),
            "per_100_words": round(100 * len(findings) / words, 2) if words else None,
            "issues": findings[:20]}


def local_language_tool(prose, text, port):
    # Only use a locally configured service, without proxies, redirects or a cloud fallback.
    with requests.Session() as session:
        session.trust_env = False
        with session.post(f"http://127.0.0.1:{port}/v2/check", data={"text": prose, "language": "en-US"},
                          allow_redirects=False, timeout=(0.25, 1.5), stream=True) as response:
            if response.status_code != 200:
                raise ValueError("Local writing service unavailable.")
            payload = bytearray()
            for block in response.iter_content(8192):
                payload.extend(block)
                if len(payload) > 131072:
                    raise ValueError("Local writing response is too large.")
    offsets, position = {0: 0}, 0
    for index, character in enumerate(prose, 1):
        position += 2 if ord(character) > 0xFFFF else 1
        offsets[position] = index
    findings = []
    for match in json.loads(payload)["matches"]:
        start = offsets.get(match["offset"])
        end = offsets.get(match["offset"] + match["length"])
        if start is None or end is None or start >= end:
            continue
        replacements = match.get("replacements") or []
        findings.append({"description": str(match["message"])[:160], "excerpt": text[start:end][:100],
                         "start": start, "suggestion": str(replacements[0]["value"])[:80] if replacements else None})
    return findings


def observed_requests(text, pattern):
    for match in pattern.finditer(text):
        if not NEGATION.search(text[max(0, match.start() - 55):match.start()]):
            return match.group()
    return ""


def email_evidence(text, sender="", links=(), subject="", reply_to="", html="", labels=()):
    subject_links = [match.group().rstrip(".,;!?)") for match in LINK.finditer(subject)]
    text, links, limited = link_items(text, html, [*links, *subject_links])
    prose = QUOTED_LINES.sub("", text)
    markers = []
    for category, section_text in (("body", prose), ("subject", subject)):
        if match := observed_requests(section_text, CREDENTIAL_REQUEST):
            markers.append(marker("credential_request", "Direct request for sensitive information",
                                  "The message asks the recipient to provide a credential or private identifier.",
                                  "high", category, excerpt=match))
            break
    pressure = PRESSURE.search(subject)
    section = "subject"
    if not pressure:
        pressure, section = PRESSURE.search(prose), "body"
    if pressure:
        markers.append(marker("pressure", "Pressure or account restriction claim",
                              "A restriction or deadline appears in the message. Verify the event independently.",
                              category=section, excerpt=pressure.group()))
    payment = observed_requests(prose, PAYMENT)
    payment_section = "body"
    if not payment:
        payment = observed_requests(subject, PAYMENT)
        payment_section = "subject"
    if payment:
        markers.append(marker("payment_request", "Request to transfer value",
                              "A payment, transfer or gift-card request merits independent verification.",
                              category=payment_section, excerpt=payment))
    if re.search(r"\b(?:prize|reward|winner|won)\b", subject, re.I):
        markers.append(marker("reward_subject", "Reward claim in subject", "Check who made the offer and why.",
                              "low", "subject"))
    if re.match(r"^\s*(?:re|fwd?)\s*:", subject, re.I):
        markers.append(marker("thread_prefix", "Reply or forward prefix", "The subject uses a thread prefix. The thread was not verified.", "low", "subject"))
    if re.search(r"[A-Z]{4,}\s+[A-Z]{4,}\s+[A-Z]{4,}", subject):
        markers.append(marker("capitalized_subject", "Capitalized subject", "Several words in the subject are capitalized.", "low", "subject"))
    if match := SECURITY_NOTICE.search(subject):
        markers.append(marker("security_notice_subject", "Security notice in subject",
                              "The subject describes a security event. The notice alone does not verify the event.",
                              "low", "subject", excerpt=match.group()))
    if VERIFY.search(subject) and prose and not ACTION.search(prose):
        markers.append(marker("subject_body_gap", "Verification claim in subject only", "The body does not contain a corresponding action request.", "low", "subject"))

    name, address = parseaddr(sender)
    domain = address.rpartition("@")[2].lower()
    reply_domain = parseaddr(reply_to)[1].rpartition("@")[2].lower()
    if domain and reply_domain and registrable(domain) != registrable(reply_domain):
        markers.append(marker("reply_domain_mismatch", "Different Reply-To domain",
                              "Replies go to a different registrable domain than the displayed sender.", category="sender"))
    if domain and lookalike_brand(domain):
        markers.append(marker("sender_lookalike", "Possible sender-domain lookalike",
                              "The sender domain uses characters that resemble a known brand name.", category="sender"))
    for brand, known_domain in BRANDS.items():
        if re.fullmatch(rf"{re.escape(brand)}(?: (?:support|security|team))?", name.strip(), re.I):
            if domain and registrable(domain) != known_domain:
                markers.append(marker("display_name_domain_mismatch", "Display name and sender domain differ",
                                      "The display name claims a brand while the address has a different registrable domain.",
                                      category="sender"))
            break

    deceptive = False
    for link in links:
        result = url_evidence(link["url"])
        link.update({key: result[key] for key in ("url", "markers", "assessment", "registrable_domain")})
        displayed_host = link.get("displayed_hostname")
        if displayed_host:
            # Displayed URLs may also contain private parameters.
            link["display_text"] = displayed_host
        if displayed_host and registrable(displayed_host) != result["registrable_domain"]:
            link["markers"].append(marker("destination_label_mismatch", "Visible and actual hosts differ",
                                          "The visible link names a different registrable domain from its destination.", "high", "link"))
            link["assessment"] = "Suspicious"
        if link["assessment"] == "Suspicious":
            deceptive = True
    if deceptive:
        markers.append(marker("link_deception", "Deceptive destination structure",
                              "At least one link hides or misrepresents its destination. See the individual link results.", "high", "link"))

    signals = {item["id"] for item in markers}
    sender_mismatch = signals & {"sender_lookalike", "display_name_domain_mismatch", "reply_domain_mismatch"}
    link_warnings = any(
        item["id"] in {"lookalike_domain", "brand_in_subdomain", "raw_ip_domain", "shortener"}
        for link in links for item in link["markers"]
    )
    verify = observed_requests(prose, VERIFY)
    flagged = "credential_request" in signals or deceptive or bool(
        (pressure and payment) or (links and verify and (link_warnings or sender_mismatch))
        or (payment and sender_mismatch)
    )
    # Sparse text with no independent context does not support a clean result.
    word_variety = len(set(re.findall(r"\b[^\W\d_]{3,}\b", prose.casefold())))
    context = bool(domain or links or subject or re.search(r"[.!?]\s+\w", prose))
    enough = word_variety >= 7 and context
    risk, assessment, explanation = outcome(markers, flagged, enough)
    return {"risk_level": risk, "assessment": assessment, "explanation": explanation, "_visible_body": text,
            "risk_score": None, "safety_score": None, "markers": markers, "links": links, "links_limited": limited,
            "subject": subject, "subject_findings": [item for item in markers if item["category"] == "subject"],
            "sender": {"display_name": name, "domain": domain, "reply_to_domain": reply_domain,
                                         "authentication": "unavailable"},
            "labels": list(labels), "grammar": writing_checks(text)}


PAGE_FEATURES = frozenset({"credential_forms", "payment_fields", "external_forms", "iframes",
                           "external_frames", "external_links", "links", "buttons", "overlays", "infection_claim",
                           "support_request", "prize_claim", "payment_request", "download_pressure", "countdown",
                           "notification_prompt", "browser_impersonation", "blocking_overlay",
                           "cross_site_navigation", "fullscreen"})
OPTIONAL_PAGE_FEATURES = frozenset({"external_credential_forms"})


def webpage_evidence(url, features):
    if not isinstance(features, dict) or not PAGE_FEATURES <= features.keys() <= PAGE_FEATURES | OPTIONAL_PAGE_FEATURES or not all(
        type(value) is int and 0 <= value <= 100 for value in features.values()
    ):
        raise ValueError("Invalid webpage observations.")
    if features.get("external_credential_forms", 0) > min(features["external_forms"], features["credential_forms"]):
        raise ValueError("Cross-origin credential forms must be counted in both form totals.")
    address = url_evidence(url)
    markers = list(address["markers"])
    tech_scam = bool(features["infection_claim"] and (features["support_request"] or features["download_pressure"]))
    payment_lure = bool(features["prize_claim"] and (features["payment_request"] or features["payment_fields"]))
    credentials = bool(features.get("external_credential_forms"))
    deceptive_overlay = bool(features["blocking_overlay"] and features["browser_impersonation"] and
                              (features["payment_request"] or features["notification_prompt"]))
    if tech_scam:
        markers.append(marker("tech_support_pressure", "Device infection and intervention request",
                              "Visible page content pairs an infection claim with a support or download request.", "high", "page"))
    if payment_lure:
        markers.append(marker("prize_payment", "Prize claim with a payment request",
                              "The page pairs a reward claim with a payment prompt or payment field.", "high", "page"))
    if credentials:
        markers.append(marker("cross_site_credentials", "Credential form action uses another host",
                              "A visible password field belongs to a form whose destination hostname differs from this page.",
                              category="form"))
    if deceptive_overlay:
        markers.append(marker("deceptive_overlay", "Browser-like overlay with a sensitive request",
                              "A blocking overlay resembles browser UI and requests a payment or notifications.", "high", "page"))
    if features["fullscreen"] or features["countdown"] or features["cross_site_navigation"]:
        markers.append(marker("page_behavior", "Fullscreen, countdown or cross-site navigation observed",
                              "These behaviors also occur on legitimate pages. Inspect the request in context.", "low", "page"))
    if features["notification_prompt"] and not deceptive_overlay:
        markers.append(marker("page_notification_prompt", "Page asks to enable notifications",
                              "This is a visible prompt, separate from the browser permission state.", "low", "page"))
    flagged = (tech_scam or payment_lure or deceptive_overlay or address["risk_level"] == "suspicious"
               or (credentials and features["browser_impersonation"]))
    risk, assessment, explanation = outcome(markers, flagged, enough=any(features.values()))
    return {"risk_level": risk, "assessment": assessment, "explanation": explanation, "markers": markers,
            "observations": features, "url_assessment": address["assessment"], "safety_score": None, "risk_score": None}
