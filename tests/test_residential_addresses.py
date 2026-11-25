"""Exact, synthetic compose spans; surrounding prose must survive redaction."""
import unittest
from pathlib import Path

from privacy_detector import PLACEHOLDERS, privacy_report

# (prefix, address, suffix). Several cases exercise different evidence with the same value.
CASES = [
    ("Address: ", "Flat 402, Example Apartments, Road No. 5, Hyderabad, Telangana 500032", ""),
    ("", "Flat 402, Example Apartments, Road No. 5, Hyderabad, Telangana 500032", ""),
    ("I live in ", "Flat 402 at Example Apartments near Sample Park in Hyderabad", "."),
    ("", "Flat 402\nExample Apartments\nRoad No. 5\nHyderabad, Telangana\n500032", ""),
    ("", "H.No. 12-34/5, Sample Colony, Hyderabad, Telangana", ""),
    ("", "Plot No. 45, Road No. 10, Example Nagar, Hyderabad", ""),
    ("", "Flat 302, Example Residency, near Sample Park, Hyderabad", ""),
    ("", "123 Example Street, Apartment 5, London, SW1A 1AA", ""),
    ("", "Flat 204, Example Residency, Sample Road, Hyderabad", ""),
    ("", "Block B, Tower 3, Willow Enclave, Sector 12, Jaipur", ""),
    ("Deliver to ", "Willow Gardens, block D, Pune", "."),
    ("My home is ", "Fern Village, Vale District", "."),
    ("", "12 Cedar Road, Toronto, ON M5V 2T6", ""),
    ("", "flat no. 9b, willow residency, hill road, pune", ""),
    ("Home address: ", "17 Copper Road", ". Bring a snack."),
    ("✨ I live in ", "Flat 7, River Gardens, near Cedar Park in Pune", " and I work downtown."),
    ("", "Flat 9, River Heights", "\nPlease bring 2 tickets."),
    ("", "Flat 12 Briar Apartments Road No. 3 Pune Maharashtra 411001", ""),
]
NEGATIVE = [
    "I live in Hyderabad.", "We visited London last year.", "The school is located near a park.",
    "Hyderabad is a major city in India.", "Meet me at the shopping mall.", "The answer is on page 123.",
    "We visited Fern Village last year.", "Oak Road is closed.", "The concert is at Willow Gardens.",
]
REVIEW = ["Flat 402", "25 Cedar Street", "P.O. Box 52", "Block C", "Sector 8, Jaipur"]
DEMO = Path(__file__).resolve().parents[1] / "docs/privacy-demo-email.txt"


class AddressTests(unittest.TestCase):
    def test_complete_address_spans(self):
        for prefix, address, suffix in CASES:
            with self.subTest(address=address, prefix=prefix):
                result = privacy_report(prefix + address + suffix)
                hit, = result["findings"]
                self.assertEqual((hit["category"], hit["start"], hit["end"], hit["ambiguous"]),
                                 ("addresses", len(prefix), len(prefix + address), False))
                self.assertEqual(result["redacted_text"], prefix + "[ADDRESS]" + suffix)

    def test_city_and_public_place_mentions(self):
        for text in NEGATIVE:
            with self.subTest(text=text):
                self.assertEqual(privacy_report(text)["findings"], [])

    def test_ambiguous_addresses_require_selection(self):
        for text in REVIEW:
            with self.subTest(text=text):
                result = privacy_report(text)
                hit, = result["findings"]
                self.assertEqual((hit["category"], hit["ambiguous"]), ("addresses", True))
                self.assertEqual(result["redacted_text"], text)
                self.assertEqual(privacy_report(text, selected=[hit["id"]])["redacted_text"], "[ADDRESS]")

    def test_demo_and_adjacent_private_fields(self):
        text = DEMO.read_text()
        result = privacy_report(text)
        self.assertEqual(result["counts"], dict.fromkeys(PLACEHOLDERS, 1))
        self.assertEqual(result["total_review"], 0)
        self.assertIn("I live in [ADDRESS].\nPostal code: [POSTAL CODE]", result["redacted_text"])
        for hit in result["findings"]:
            self.assertNotIn(text[hit["start"]:hit["end"]], result["redacted_text"])
