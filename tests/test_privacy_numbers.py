"""Synthetic privacy acceptance cases and numeric boundary regressions."""
import unittest

from stdnum import verhoeff

from privacy_detector import PLACEHOLDERS, privacy_report


def with_checksum(base):
    return base + verhoeff.calc_check_digit(base)


AADHAAR = with_checksum("73456789012")
DETECTIONS = [
    ("Email", "student@example.org", "emails"),
    ("Mobile", "9123456789", "phone_numbers"),
    ("WhatsApp", "+91 91234 56789", "phone_numbers"),
    ("Telephone", "+1 (202) 555-0103", "phone_numbers"),
    ("Aadhaar", AADHAAR, "aadhaar_numbers"),
    ("UIDAI", f"{AADHAAR[:4]}-{AADHAAR[4:8]}-{AADHAAR[8:]}", "aadhaar_numbers"),
    ("Mailing address", "18 Oak Road", "addresses"),
    ("Postcode", "SW1A 1AA", "postal_codes"),
    ("PIN code", "110001", "postal_codes"),
    ("SSN", "123-45-6789", "ssn_numbers"),
    ("Bank account", "12345678901234", "bank_accounts"),
    ("IFSC", "ABCD0123456", "ifsc_codes"),
    ("IBAN", "GB82 WEST 1234 5698 7654 32", "iban_numbers"),
    ("Credit card", "4111 1111 1111 1111", "card_numbers"),
    ("Debit card", "5555 5555 5555 4444", "card_numbers"),
    ("PAN", "ABCPA1234Z", "pan_numbers"),
    ("Passport", "A1234567", "passport_numbers"),
    ("UPI ID", "student@bank", "upi_ids"),
    ("Password", "sample-only-pass", "passwords"),
    ("API key", "example_key_12345", "api_keys"),
    ("Session token", "sample_token_12345", "auth_tokens"),
]

# None means the value must be absent even from the optional review list.
NEGATIVES = [
    ("Aadhaar: 2345 6789 0122", "aadhaar_numbers"),
    ("Phone: 1234567890", "phone_numbers"),
    ("The population is 9876543210.", None),
    ("Calculate 123456789012 + 1234567890.", None),
    ("Order ID: 9123456789", None),
    (f"Tracking number: {AADHAAR}", None),
    ("Invoice number: 9123456789", None),
    (f"Product code: {AADHAAR}", None),
    ("Transaction reference: 9123456789", None),
    ("Reference ID: +91 91234 56789", None),
    ("The counter read 110001.", None),
    ("Logged at 2026-11-24 13:15:09.", None),
]


class NumericPrivacyTests(unittest.TestCase):
    def test_sensitive_detection_cases(self):
        for label, value, kind in DETECTIONS:
            with self.subTest(label=label):
                text = f"{label}: {value}"
                report = privacy_report(text)
                hit, = report["findings"]
                self.assertEqual((hit["category"], hit["ambiguous"]), (kind, False))
                self.assertEqual(text[hit["start"]:hit["end"]], value)
                self.assertEqual(report["redacted_text"], f"{label}: {PLACEHOLDERS[kind]}")

    def test_false_positive_cases(self):
        for text, review_kind in NEGATIVES:
            with self.subTest(text=text):
                report = privacy_report(text)
                self.assertEqual(report["redacted_text"], text)
                self.assertEqual(report["total_redacted"], 0)
                if review_kind is None:
                    self.assertEqual(report["findings"], [])
                else:
                    hit, = report["findings"]
                    self.assertEqual((hit["category"], hit["ambiguous"]), (review_kind, True))
                    self.assertFalse(report["review"][0]["approved"])

    def test_failed_validations_cannot_fall_back_to_another_category(self):
        # The first base is an Indian dialling code followed by a mobile number.
        for base in ("91912345678", "65324198761", "87314596218"):
            valid = with_checksum(base)
            for digit in "0123456789":
                with self.subTest(base=base, digit=digit):
                    hit, = privacy_report("Aadhaar: " + base + digit)["findings"]
                    self.assertEqual(hit["category"], "aadhaar_numbers")
                    self.assertEqual(hit["ambiguous"], digit != valid[-1])
                    self.assertEqual(hit["validation"], "checksum_valid" if digit == valid[-1]
                                     else "invalid_format_or_checksum")
        for label, value in [("Phone", AADHAAR), ("Aadhaar", "+91 91234 56789"),
                             ("Aadhaar", "9123456789"), ("Aadhaar", with_checksum("13456789012"))]:
            with self.subTest(label=label, value=value):
                hit, = privacy_report(f"{label}: {value}")["findings"]
                self.assertTrue(hit["ambiguous"])
                self.assertEqual(hit["category"], "phone_numbers" if label == "Phone" else "aadhaar_numbers")

    def test_country_plan_and_number_type(self):
        cases = [
            ("US", "Phone: 2125550104", "number_plan_valid"),
            ("CA", "Phone: 2125550104", "invalid_number_plan"),
            ("CA", "Phone: +1 212-555-0104", "number_plan_valid"),
            ("GB", "Phone: 020 7946 0018", "number_plan_valid"),
            ("US", "Phone: 020 7946 0018", "invalid_number_plan"),
            ("IN", "Phone: 8041234567", "ambiguous_fixed_line"),
            ("IN", "Phone: 80412345-67", "ambiguous_fixed_line"),
            ("IN", "Phone: 80 41234567", "number_plan_valid"),
            ("IN", "Phone: 08041234567", "number_plan_valid"),
            ("IN", "Mobile: 080 4123 4567", "not_mobile_number"),
            ("IN", "Phone: +1 (202) 555-0101 ext. 25", "number_plan_valid"),
            ("IN", "Phone: +999 3123456789", "invalid_number_plan"),
        ]
        for region, text, expected in cases:
            with self.subTest(region=region, text=text):
                hit, = privacy_report(text, region=region)["findings"]
                self.assertEqual(hit["validation"], expected)
                self.assertEqual(hit["ambiguous"], expected != "number_plan_valid")

    def test_a_grouped_identifier_suffix_is_not_an_independent_aadhaar(self):
        grouped = f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}"
        # This particular 16-digit grouping passes Luhn as a whole.
        hit, = privacy_report("4567 " + grouped)["findings"]
        self.assertEqual((hit["category"], hit["start"], hit["end"], hit["ambiguous"]),
                         ("card_numbers", 0, len("4567 " + grouped), True))
        for prefix in ("9999 ", "Tracking number: 4567 "):
            with self.subTest(prefix=prefix):
                self.assertEqual(privacy_report(prefix + grouped)["findings"], [])

    def test_alternative_international_contacts_remain_detectable(self):
        text = "Telephone: +12025550103 / +442079460018"
        self.assertEqual(privacy_report(text)["redacted_text"], "Telephone: [PHONE] / [PHONE]")

    def test_quantities_and_operands_never_reach_the_review_list(self):
        for text in [
            "The population of the district rose to 8123456789.",
            "The total is approximately 9123456789.", "There were 7123456789 residents.",
            f"({AADHAAR}) - (9123456789)", f"{AADHAAR} × 9123456789", f"{AADHAAR}/7",
            f"9 ** {AADHAAR}", f"8 divided by {AADHAAR}", "12 + (+91 91234 56789)",
            "Subtract 9123456789 from 8123456789.", f"The product of {AADHAAR} and 7.",
        ]:
            with self.subTest(text=text):
                self.assertEqual(privacy_report(text)["findings"], [])

    def test_only_selected_occurrence_is_redacted(self):
        value = "8123456789"
        text = f"✨ Count: {value}. Phone: {value}. Aadhaar: {value}. Mobile: {value}."
        result = privacy_report(text)
        first, review, last = result["findings"]
        self.assertEqual([h["ambiguous"] for h in (first, review, last)], [False, True, False])
        self.assertEqual(privacy_report(text, selected=[review["id"]])["redacted_text"],
                         text.replace("Aadhaar: " + value, "Aadhaar: [AADHAAR]"))
        self.assertEqual(privacy_report(text, selected=[last["id"]])["redacted_text"],
                         text.replace("Mobile: " + value, "Mobile: [PHONE]"))
