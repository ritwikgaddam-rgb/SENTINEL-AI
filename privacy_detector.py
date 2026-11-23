import re


# A single pass gives an email priority over a phone-like number in its address.
PRIVATE_INFO = re.compile(
    r"(?P<emails>(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b)"
    r"|(?P<phone_numbers>(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d))"
    r"|(?P<aadhaar_numbers>(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d))"
)
REPLACEMENTS = {
    "emails": "[EMAIL]",
    "phone_numbers": "[PHONE]",
    "aadhaar_numbers": "[AADHAAR]",}


def detect_private_info(text):
    matches = {category: [] for category in REPLACEMENTS}
    for match in PRIVATE_INFO.finditer(text):
        matches[match.lastgroup].append(match.group())
    return matches


def redact_private_info(text):
    # Replace each matched span so a short address cannot alter a longer one.
    return PRIVATE_INFO.sub(lambda match: REPLACEMENTS[match.lastgroup], text)


if __name__ == "__main__":
    sample = """
My email is student@example.com.
My second email is hello@gmail.com.
My phone number is 9876543210.
My other number is +91 9123456780.
My Aadhaar test number is 1234 5678 9012.
This sentence has no private information.
"""

    print(redact_private_info(sample))
