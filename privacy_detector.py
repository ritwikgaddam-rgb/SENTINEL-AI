import re

def detect_private_info(text):
    emails = []
    phones = []
    aadhaar = []
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    phone_pattern = r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"
    aadhaar_pattern = r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"
    emails = re.findall(email_pattern, text)
    phones = re.findall(phone_pattern, text)
    aadhaar = re.findall(aadhaar_pattern, text)
    return {
        "emails": emails,
        "phone_numbers": phones,
        "aadhaar_numbers": aadhaar}

def redact_private_info(text):
    results = detect_private_info(text)
    for email in results["emails"]:
        text = text.replace(email, "[EMAIL]")
    for phone in results["phone_numbers"]:
        text = text.replace(phone, "[PHONE]")
    for aadhaar in results["aadhaar_numbers"]:
        text = text.replace(aadhaar, "[AADHAAR]")
    return text

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