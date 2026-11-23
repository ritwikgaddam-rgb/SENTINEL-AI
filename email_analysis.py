"""Local writing checks and explanations for the fitted email model."""

import ipaddress
import json
import os
import re
from urllib.parse import urlsplit

import requests


LINK = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
PRIVATE_SYNTAX = re.compile(rf"{LINK.pattern}|(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{{2,}}", re.IGNORECASE)
COMMON_MISSPELLINGS = {
    "acount": "account",
    "adress": "address",
    "definately": "definitely",
    "immediatly": "immediately",
    "neccessary": "necessary",
    "occured": "occurred",
    "recieve": "receive",
    "seperate": "separate",
    "sucessful": "successful",
    "teh": "the",
    "wierd": "weird",
}
SPELLING = re.compile(r"\b(" + "|".join(COMMON_MISSPELLINGS) + r")\b", re.IGNORECASE)
LANGUAGES = {"en": "en-US", "en-us": "en-US", "en-gb": "en-GB"}
ISSUE_TYPES = ("spelling", "grammar", "repeated_word", "punctuation", "other")
MAX_ISSUES = 12
MAX_ISSUE_BYTES = 7000
MAX_TOOL_RESPONSE = 512 * 1024

# Deliberately narrow rules for common errors in English prose.
WRITING_RULES = (
    (
        "singular_agreement", "grammar",
        r"\b(?:your|this|the)\s+(?:account|profile|subscription|membership)\s+(?P<issue>have)\s+been\b",
        "This singular subject takes ‘has’.", ["has"],
    ),
    (
        "plural_agreement", "grammar", r"\b(?:we|you|they)\s+(?P<issue>is)\b",
        "This pronoun usually takes ‘are’.", ["are"],
    ),
    (
        "pronoun_agreement", "grammar", r"\b(?:he|she|it)\s+(?P<issue>are)\b",
        "This singular pronoun usually takes ‘is’.", ["is"],
    ),
    (
        "repeated_word", "repeated_word", r"\b(?P<word>[A-Za-z]{2,})[ \t]{1,3}(?P<issue>(?P=word))\b",
        "Check whether this adjacent word repetition is intended.", [],
    ),
    (
        "space_before_punctuation", "punctuation", r"[A-Za-z](?P<issue>[ \t]+)[,.!?;](?=\s|$)",
        "Remove the space before the punctuation mark.", [""],
    ),
)


def _finding(code, kind, description, start, end, suggestions):
    return {
        "code": code,
        "kind": kind,
        "description": description,
        "offset": start,
        "length": end - start,
        "suggestions": suggestions,
    }


def _masked_prose(text, spans, placeholder):
    # Keep text positions while excluding addresses and embedded URL syntax.
    fragments = []
    end = 0
    for start, stop in spans:
        fragments.append(text[end:start])
        fragments.append(placeholder * (stop - start))
        end = stop
    return "".join(fragments) + text[end:]


def _builtin_issues(text):
    for code, kind, pattern, description, suggestions in WRITING_RULES:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            start, end = match.span("issue")
            if match["issue"].istitle():
                replacements = [item.capitalize() for item in suggestions]
            else:
                replacements = suggestions
            yield _finding(code, kind, description, start, end, replacements)
    for match in SPELLING.finditer(text):
        replacement = COMMON_MISSPELLINGS[match[0].lower()]
        if match[0].istitle():
            replacement = replacement.capitalize()
        yield _finding("common_misspelling", "spelling", "This word appears to be misspelled.", *match.span(), [replacement])


def _utf16_offsets(text):
    # LanguageTool runs on Java. Translate its offsets into Python text positions.
    offsets = {0: 0}
    position = 0
    for index, character in enumerate(text, start=1):
        position += 2 if ord(character) > 0xFFFF else 1
        offsets[position] = index
    return offsets


def _tool_text(value, limit):
    if not isinstance(value, str):
        raise ValueError("Invalid LanguageTool text field.")
    # Replace malformed Unicode so a local tool response cannot prevent JSON output.
    return value[:limit].encode("utf-8", errors="replace").decode("utf-8")


def _language_tool_issues(text, language, port, masked_spans):
    if not port.isascii() or not port.isdecimal() or len(port) > 5 or not 1 <= int(port) <= 65535:
        raise ValueError("Expected a numeric local LanguageTool port.")
    with requests.Session() as session:
        session.trust_env = False
        # The only configurable part of the local endpoint is its numeric port.
        with session.post(
            f"http://127.0.0.1:{int(port)}/v2/check",
            data={"text": text, "language": language},
            allow_redirects=False,
            timeout=(0.5, 3),
            stream=True,
        ) as response:
            if response.status_code != 200:
                raise ValueError("Local LanguageTool returned an error.")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=16384):
                body.extend(chunk)
                if len(body) > MAX_TOOL_RESPONSE:
                    raise ValueError("Local LanguageTool response was too large.")

    matches = json.loads(body)["matches"]
    if not isinstance(matches, list):
        raise ValueError("Invalid LanguageTool matches.")
    offsets = _utf16_offsets(text)
    for match in matches:
        raw_start = match["offset"]
        raw_end = raw_start + match["length"]
        if raw_start not in offsets or raw_end not in offsets or raw_end <= raw_start:
            continue
        start, end = offsets[raw_start], offsets[raw_end]
        if any(start < mask_end and end > mask_start for mask_start, mask_end in masked_spans):
            continue
        rule = match["rule"]
        code = _tool_text(rule["id"], 48)
        issue_type = rule.get("issueType")
        category = rule.get("category", {}).get("id")
        if issue_type == "misspelling":
            kind = "spelling"
        elif "WORD_REPEAT" in code:
            kind = "repeated_word"
        elif category in {"PUNCTUATION", "TYPOGRAPHY"}:
            kind = "punctuation"
        else:
            kind = "grammar" if issue_type == "grammar" else "other"
        suggestions = [_tool_text(item["value"], 48) for item in match.get("replacements", [])[:2]]
        yield _finding(code, kind, _tool_text(match["message"], 160), start, end, suggestions)


def _writing_result(issues, status, language, provider=None, reason=None):
    unique = {}
    for issue in issues:
        key = issue["kind"], issue["offset"], issue["length"]
        unique.setdefault(key, issue)
    ordered = sorted(unique.values(), key=lambda issue: (issue["offset"], issue["length"]))
    displayed = []
    remaining_bytes = MAX_ISSUE_BYTES
    for issue in ordered[:MAX_ISSUES]:
        # Count escapes conservatively so both web and Tauri responses stay small.
        remaining_bytes -= len(json.dumps(issue, ensure_ascii=True)) + 2
        if remaining_bytes < 0:
            break
        displayed.append(issue)
    available = provider is not None
    counts = {
        f"{kind}_issues": sum(issue["kind"] == kind for issue in ordered) if available else None
        for kind in ISSUE_TYPES
    }
    return {
        "available": available,
        "status": status,
        "language": language,
        "provider": provider,
        "reason": reason,
        "total_issues": len(ordered) if available else None,
        **counts,
        "issues": displayed,
        "issues_truncated": len(displayed) < len(ordered),
    }


def check_grammar(text, language="en"):
    """Analyze English writing without sending text to external services."""
    language = LANGUAGES.get(language.lower())
    if language is None:
        return _writing_result([], "unsupported_language", None, reason="Writing checks support English.")
    masked_spans = [match.span() for match in PRIVATE_SYNTAX.finditer(text)]
    port = os.getenv("SENTINELAI_LANGUAGETOOL_PORT")
    reason = "Built-in English checks cover a limited set of common errors."
    if port is not None:
        try:
            prose = _masked_prose(text, masked_spans, " ")
            issues = _language_tool_issues(prose, language, port, masked_spans)
            return _writing_result(issues, "analyzed", language, "languagetool")
        except (requests.RequestException, AttributeError, ValueError, TypeError, KeyError):
            reason = "Local LanguageTool is unavailable. Limited built-in checks were used."
    prose = _masked_prose(text, masked_spans, "\uFFFC")
    return _writing_result(_builtin_issues(prose), "limited", language, "builtin", reason)


DEADLINE = r"(?:immediately|right away|within (?:the next )?\d{1,3} (?:minutes?|hours?))\b"
WARNING_RULES = (
    (
        "immediate_action", "urgency", r"\b(?:act|respond|verify|confirm|reply)\s+" + DEADLINE,
        "The text requests immediate action or gives a short deadline.",
    ),
    (
        "suspension_threat", "urgency", r"\b(?:account|access)\s+(?:will|may)\s+be\s+(?:suspended|disabled|locked)\b",
        "The text warns that an account or access may be disabled.",
    ),
    (
        "sensitive_request", "sensitive_information",
        r"\b(?:send|submit|provide|share|reply with|enter)\s+(?:(?:us|me)\s+)?(?:your|the)\s+"
        r"(?:current\s+|account\s+)?(?:password|otp|verification code|one-time (?:code|password)|"
        r"(?:credit|debit) card (?:number|details)|bank account (?:number|details)|social security number|aadhaar number)\b",
        "The text specifically asks the recipient to provide sensitive information.",
    ),
    (
        "urgent_transfer", "financial_pressure",
        r"\b(?:send|wire|transfer)\s+(?:the\s+|this\s+)?(?:funds|payment|money)\s+" + DEADLINE,
        "The text requests a transfer under time pressure.",
    ),
)
NEGATION = re.compile(r"\b(?:do not|don['’]t|never|avoid|without|not)\s+(?:ever\s+)?$", re.IGNORECASE)


def warning_signs(text):
    def observed(code, category, description, start, end):
        return {"code": code, "category": category, "description": description, "offset": start, "length": end - start}

    findings = []
    prose = _masked_prose(text, (match.span() for match in PRIVATE_SYNTAX.finditer(text)), "\uFFFC")
    for code, category, pattern, description in WARNING_RULES:
        for match in re.finditer(pattern, prose, re.IGNORECASE):
            if not NEGATION.search(text[max(0, match.start() - 35):match.start()]):
                findings.append(observed(code, category, description, *match.span()))
                break

    link_findings = {}
    for match in LINK.finditer(text):
        address = match[0].rstrip(".,;!?)")
        try:
            parts = urlsplit(address)
            host = parts.hostname
        except ValueError:
            continue
        if not host:
            continue
        if parts.username is not None:
            link_findings.setdefault("userinfo_link", observed(
                "userinfo_link", "link_structure", "A link contains user information before its actual host.",
                match.start(), match.start() + len(address),
            ))
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue
        link_findings.setdefault("ip_address_link", observed(
            "ip_address_link", "link_structure", "A link uses a numeric IP address as its host.",
            match.start(), match.start() + len(address),
        ))
    return sorted(findings + list(link_findings.values()), key=lambda issue: issue["offset"])


def explain_email_model(text, model, *, feature_row=None):
    """Report exact signed contributions to the model's phishing log-odds."""
    vectorizer = model.named_steps["tfidf"]
    classifier = model.named_steps["classifier"]
    classes = list(classifier.classes_)
    if len(classes) != 2 or 1 not in classes:
        raise ValueError("Expected a fitted binary email model with phishing label 1.")
    direction = 1 if classes[1] == 1 else -1
    row = vectorizer.transform([text]) if feature_row is None else feature_row
    contributions = [
        (index, float(value), float(classifier.coef_[0, index]) * direction)
        for index, value in zip(row.indices, row.data)
    ]
    intercept = float(classifier.intercept_[0]) * direction
    net = sum(value * coefficient for _, value, coefficient in contributions)
    evidence = {
        "feature_count": len(contributions),
        "intercept_log_odds": intercept,
        "feature_log_odds": net,
        "total_log_odds": intercept + net,
    }
    ordered = sorted(contributions, key=lambda item: item[1] * item[2])
    legitimate = [item for item in ordered if item[2] < 0][:4]
    phishing = [item for item in reversed(ordered) if item[2] > 0][:4]
    names = vectorizer.get_feature_names_out()
    return evidence, [
        {
            "feature": str(names[index]),
            "tfidf": value,
            "coefficient": coefficient,
            "contribution_log_odds": value * coefficient,
            "toward": "phishing" if coefficient > 0 else "legitimate",
        }
        for index, value, coefficient in phishing + legitimate
    ]


def analyze_email(text, model, *, language="en", feature_row=None):
    evidence, contributions = explain_email_model(text, model, feature_row=feature_row)
    return {
        "grammar": check_grammar(text, language),
        "warning_signs": warning_signs(text),
        "model_evidence": evidence,
        "model_contributions": contributions,
    }
