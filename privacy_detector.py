"""Local validation and position-based privacy redaction."""
import re
from dataclasses import dataclass
from threading import Lock

import phonenumbers
from stdnum import verhoeff, iban, luhn

try:
    import usaddress
except ImportError:
    usaddress = None

PLACEHOLDERS = {
    "emails": "[EMAIL]",
    "phone_numbers": "[PHONE]",
    "aadhaar_numbers": "[AADHAAR]",
    "addresses": "[ADDRESS]",
    "postal_codes": "[POSTAL CODE]",
    "ssn_numbers": "[SSN]",
    "bank_accounts": "[BANK ACCOUNT]",
    "ifsc_codes": "[IFSC]",
    "iban_numbers": "[IBAN]",
    "card_numbers": "[CARD]",
    "pan_numbers": "[PAN]",
    "passport_numbers": "[PASSPORT]",
    "upi_ids": "[UPI]",
    "passwords": "[PASSWORD]",
    "api_keys": "[API KEY]",
    "auth_tokens": "[TOKEN]",
}

ORDINARY_ID = re.compile(
    r"\b(?:order|invoice|tracking|reference|product|transaction|customer|ticket)"
    r"(?:[ \t]+(?:number|id|no\.?|code)){0,2}[ \t]*[:=#-]?[ \t]*$", re.I
)
NUMBER_KINDS = {"aadhaar_numbers", "phone_numbers", "ssn_numbers", "card_numbers"}
US_ADDRESS = re.compile(
    r"^[ \t]*((?:[0-9]{1,6}\b|P\.?[ \t]*O\.?[ \t]+Box\b)[^;\r\n]{4,165}?"
    r"\b[A-Z]{2}[ \t]+[0-9]{5}(?:-[0-9]{4})?)[ \t]*[.]?[ \t]*$",
    re.M | re.I,
)
ADDRESS_PARSER_LOCK = Lock()  # The library reuses a single local CRF tagger.


def is_us_address(value):
    if usaddress is None:
        return False
    with ADDRESS_PARSER_LOCK:
        fields = {label for _, label in usaddress.parse(value)}
    return {"PlaceName", "StateName", "ZipCode"} <= fields and (
        {"AddressNumber", "StreetName"} <= fields or "USPSBoxID" in fields
    )


def digits(value):
    return re.sub(r"[^0-9]", "", value)


def valid_card(value):
    number = digits(value)
    return len(set(number)) > 1 and number[0] != "0" and luhn.is_valid(number)


@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    kind: str
    confidence: str

    @property
    def id(self):
        return f"{self.start}:{self.end}:{self.kind}"


def find_findings(text, region="IN"):
    matches = []

    def add(kind, start, end, confidence="high"):
        if start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
            return
        if end < len(text) and (text[end].isalnum() or text[end] == "_"):
            return
        if confidence == "review" and kind in NUMBER_KINDS and ORDINARY_ID.search(text[max(0, start - 65):start]):
            return
        if kind in NUMBER_KINDS and (re.search(r"[0-9][ \t-]{0,3}-$", text[max(0, start - 6):start])
                                     or re.match(r"-[ \t-]{0,3}[0-9]", text[end:end + 6])):
            return
        matches.append(Finding(start, end, kind, confidence))

    def detect(kind, pattern, validator=None, confidence="high"):
        for match in re.finditer(pattern, text, re.IGNORECASE):
            start, end = match.span(1)
            value = match.group(1)

            if validator is None or validator(value):
                add(kind, start, end, confidence)

    # Email addresses
    detect(
        "emails",
        r"(?<![\w.%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63})\b"
    )

    # Phone numbers: require valid format and context
    for match in phonenumbers.PhoneNumberMatcher(text, region, max_tries=250):
        if not phonenumbers.is_valid_number(match.number):
            continue

        context = text[max(0, match.start - 60):match.start]

        labelled = re.search(
            r"\b(?:phone|mobile|telephone|contact|call|tel|whatsapp|text)"
            r"(?:[ \t]+(?:number|no\.?|me|us))?"
            r"[ \t]*(?:(?:is|at)[ \t]+)?[:=]?[ \t]*$",
            context,
            re.IGNORECASE
        )

        if ORDINARY_ID.search(context):
            continue
        if labelled or match.raw_string.startswith("+"):
            add("phone_numbers", match.start, match.end)
        else:
            add("phone_numbers", match.start, match.end, "review")

    # Aadhaar: context and checksum validation
    detect(
        "aadhaar_numbers",
        r"\b(?:aadhaar|aadhar|uidai)"
        r"(?:\s+(?:number|no\.?))?\s*(?:is\s*)?[:=]?\s*"
        r"([2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4})(?![\w-]|[ -]?[0-9])",
        lambda value: verhoeff.is_valid(digits(value))
    )
    detect("aadhaar_numbers", r"(?<![\w-])([2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4})(?![\w-]|[ -]?[0-9])",
           lambda value: verhoeff.is_valid(digits(value)), "review")

    # US Social Security numbers
    def valid_ssn(value):
        number = digits(value)
        return (
            len(number) == 9
            and number[:3] not in ("000", "666")
            and int(number[:3]) < 900
            and number[3:5] != "00"
            and number[5:] != "0000"
        )

    detect(
        "ssn_numbers",
        r"\b([0-9]{3}-[0-9]{2}-[0-9]{4})\b",
        valid_ssn, "review"
    )

    detect(
        "ssn_numbers",
        r"\b(?:ssn|social security number)"
        r"\s*(?:is\s*)?[:=]?\s*([0-9]{3}-?[0-9]{2}-?[0-9]{4})(?![\w-])",
        valid_ssn
    )

    # Indian PIN codes and US ZIP codes
    detect(
        "postal_codes",
        r"\b(?:pin\s*code|postal\s*code|zip(?:\s*code)?|postcode)"
        r"\s*(?:is\s*)?[:=]?\s*"
        r"([0-9]{5}-[0-9]{4}|[1-9][0-9]{5}|[0-9]{4,5}|"
        r"[0-9]{4}-[0-9]{3}|[0-9]{3}-[0-9]{4}|[0-9]{2}-[0-9]{3}|"
        r"[A-Z][0-9][A-Z][ -]?[0-9][A-Z][0-9]|[A-Z]{1,2}[0-9][0-9A-Z]? [0-9][A-Z]{2})(?![\w-])"
    )

    # Bank account numbers
    detect(
        "bank_accounts",
        r"\b(?:bank\s+account|savings\s+account|checking\s+account)"
        r"(?:\s+(?:number|no\.?))?\s*(?:is\s*)?[:=]?\s*"
        r"((?:[0-9][ -]?){7,17}[0-9])(?![\w-]|[ -]?[0-9])"
    )

    # Indian IFSC codes
    detect(
        "ifsc_codes",
        r"\bIFSC(?:\s+code)?\s*[:=]?\s*([A-Z]{4}0[A-Z0-9]{6})\b"
    )

    # IBAN numbers
    # Test at token boundaries so trailing prose cannot consume the account span.
    for match in re.finditer(
        r"\bIBAN(?:[ \t]+number)?[ \t]*[:=]?[ \t]*([A-Z]{2}[0-9]{2}[A-Z0-9]*(?:[ \t]+[A-Z0-9]+){0,7})",
        text, re.I,
    ):
        value, start = match.group(1), match.start(1)
        for token in re.finditer(r"[A-Z0-9]+", value, re.I):
            compact = iban.compact(value[:token.end()])
            if len(compact) > 34:
                break
            if len(compact) >= 15 and iban.is_valid(compact):
                add("iban_numbers", start, start + token.end())
                break
    detect("iban_numbers", r"\b([A-Z]{2}[0-9]{2}[A-Z0-9]{11,30})\b",
           lambda value: iban.is_valid(value.upper()), "review")

    # Payment cards: checksum and context
    detect(
        "card_numbers",
        r"\b(?:credit card|debit card|card number)"
        r"(?:\s+number)?\s*[:=]?\s*"
        r"((?:[0-9][ -]?){12,18}[0-9])(?![ -]?[0-9]|[\w-])",
        valid_card
    )
    detect("card_numbers", r"(?<![\w-])((?:[0-9]{4}[ -]){3}[0-9]{4})(?![\w-])",
           valid_card, "review")

    detect("pan_numbers", r"\bPAN(?:\s*(?:card|number|no\.?))?\s*[:=]?\s*([A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z])\b")
    detect("passport_numbers", r"\bpassport\s*(?:number|no\.)?\s*[:=]\s*([A-Z0-9]{6,12})\b",
           lambda value: any(char.isdigit() for char in value))
    detect("upi_ids", r"\b(?:UPI(?:\s+ID)?|VPA)\s*[:=]\s*([\w.-]{2,100}@[A-Z][A-Z0-9_-]{1,30})\b")
    detect("passwords", r'\b(?:password|passphrase|passwd)\s*[:=]\s*"([^"\r\n]{4,128})"')
    detect("passwords", r"\b(?:password|passphrase|passwd)\s*[:=]\s*'([^'\r\n]{4,128})'")
    detect("passwords", r"\b(?:password|passphrase|passwd)\s*[:=]\s*([^\s\"',;]{4,128})(?=[\s,;]|$)",
           lambda value: value.lower() not in {"required", "reset", "incorrect", "unknown", "hidden", "redacted"})
    detect("api_keys", r"\b(?:api[ _-]?key|client[ _-]?secret)\s*[:=]\s*[\"']?([A-Z0-9_./+=-]{12,512})(?![A-Z0-9_./+=-])")
    detect("auth_tokens", r"\b(?:bearer\s+|(?:(?:access|refresh|session|oauth|auth)[ _-]?)?token\s*[:=]\s*[\"']?)([A-Z0-9_./+=-]{12,1024})(?![A-Z0-9_./+=-])")
    detect("auth_tokens", r"\b(eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,})\b")

    # Explicitly labelled residential or mailing addresses
    detect(
        "addresses",
        r"\b(?:home address|residential address|mailing address|"
        r"shipping address|address)\s*(?:is\s*|[:=]\s*)"
        r"([^\n;]{8,180}?)\s*(?=\n|;|$|(?:email|phone|fax|password|postal code)\s*[:=])",
        lambda value: bool(re.search(r"[0-9]", value) and re.search(r"[A-Za-z]{2,}", value))
    )
    detect("addresses", r"\b([0-9]{1,6}[ \t]+(?:[^\W\d_][\w.'’-]*[ \t]+){1,5}"
           r"(?:street|road|avenue|lane|drive|boulevard|court|st|rd|ave|ln|dr|blvd|ct))\b",
           confidence="review")
    detect("addresses", r"\b(P\.?\s*O\.?\s+Box\s+[0-9]{1,10})\b", confidence="review")
    for match in US_ADDRESS.finditer(text):
        value = match.group(1)
        if is_us_address(value):
            add("addresses", *match.span(1))

    # Resolve overlapping detections
    # A stronger or enclosing match takes precedence over a partial suggestion.
    matches.sort(key=lambda hit: (hit.confidence != "high", hit.start, hit.start - hit.end))
    occupied = bytearray(len(text))
    resolved = []
    for hit in matches:
        if not any(occupied[hit.start:hit.end]):
            occupied[hit.start:hit.end] = b"\x01" * (hit.end - hit.start)
            resolved.append(hit)
    return sorted(resolved, key=lambda hit: hit.start)


def find_private_spans(text):
    return [(hit.start, hit.end, hit.kind) for hit in find_findings(text) if hit.confidence == "high"]


def detect_private_info(text):
    results = {kind: [] for kind in PLACEHOLDERS}

    for start, end, kind in find_private_spans(text):
        results[kind].append(text[start:end])

    return results


def privacy_report(text, approved=(), region="IN"):
    selected = set(approved)
    detected = {kind: [] for kind in PLACEHOLDERS}
    reviews, redactions, pieces = [], [], []
    cursor = 0
    for hit in find_findings(text, region):
        value = text[hit.start:hit.end]
        if hit.confidence == "review":
            reviews.append({"id": hit.id, "category": hit.kind, "start": hit.start, "end": hit.end,
                            "excerpt": value, "suggested_replacement": PLACEHOLDERS[hit.kind],
                            "approved": hit.id in selected})
            if hit.id not in selected:
                continue
        detected[hit.kind].append(value)
        redactions.append({"start": hit.start, "end": hit.end, "replacement": PLACEHOLDERS[hit.kind]})
        pieces.extend((text[cursor:hit.start], PLACEHOLDERS[hit.kind]))
        cursor = hit.end
    pieces.append(text[cursor:])
    counts = {kind: len(values) for kind, values in detected.items()}
    return {"original_length": len(text), "offset_encoding": "unicode_code_points",
            "redacted_text": "".join(pieces), "detected": detected, "counts": counts,
            "total_redacted": sum(counts.values()), "total_review": len(reviews),
            "review": reviews, "redactions": redactions}


def redact_private_info(text):
    return privacy_report(text)["redacted_text"]
