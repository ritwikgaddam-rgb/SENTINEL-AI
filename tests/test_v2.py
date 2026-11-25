import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from stdnum import verhoeff
import privacy_detector
from backend import server
from backend.database import SCAN_SCHEMA
from backend.assessments import PAGE_FEATURES, webpage_evidence, writing_checks
from training.train_reviewed_features import read_features, read_masked_email, train


class PrivacyTests(unittest.TestCase):
    def test_each_category_can_be_redacted_in_isolation(self):
        base = "23456789012"
        cases = {
            "emails": "Email: demo@example.org",
            "phone_numbers": "Phone: +1 202-555-0100",
            "aadhaar_numbers": "Aadhaar: " + base + verhoeff.calc_check_digit(base),
            "addresses": "Mailing address: 18 Oak Road",
            "postal_codes": "Postal code: SW1A 1AA",
            "ssn_numbers": "SSN: 123-45-6789",
            "bank_accounts": "Bank account: 12345678901234",
            "ifsc_codes": "IFSC: ABCD0123456",
            "iban_numbers": "IBAN: GB82 WEST 1234 5698 7654 32",
            "card_numbers": "Debit card: 5555 5555 5555 4444",
            "pan_numbers": "PAN: ABCPA1234Z",
            "passport_numbers": "Passport: A1234567",
            "upi_ids": "UPI ID: demo@bank",
            "passwords": "Password: test-secret",
            "api_keys": "API key: demo_key_12345678",
            "auth_tokens": "Bearer sample_token_12345678",
        }
        self.assertEqual(cases.keys(), privacy_detector.PLACEHOLDERS.keys())
        for kind, text in cases.items():
            with self.subTest(kind=kind):
                report = privacy_detector.privacy_report(text)
                self.assertEqual(report["total_redacted"], 1)
                self.assertEqual(report["counts"][kind], 1)
                self.assertIn(privacy_detector.PLACEHOLDERS[kind], report["redacted_text"])

    def test_context_and_checksums_prevent_numeric_false_redaction(self):
        aadhaar = "23456789012" + verhoeff.calc_check_digit("23456789012")
        text = f"Order ID: 9876543210; Reference ID: {aadhaar}; Aadhaar: {aadhaar}; Phone: +1 202-555-0100"
        report = privacy_detector.privacy_report(text)
        self.assertEqual(report["redacted_text"],
                         f"Order ID: 9876543210; Reference ID: {aadhaar}; Aadhaar: [AADHAAR]; Phone: [PHONE]")
        invalid = aadhaar[:-1] + str((int(aadhaar[-1]) + 1) % 10)
        self.assertEqual(privacy_detector.privacy_report("Aadhaar: " + invalid)["total_redacted"], 0)
        self.assertEqual(privacy_detector.privacy_report(f"Aadhaar: {aadhaar}1")["total_redacted"], 0)

    def test_categories_and_review_count_positions(self):
        text = ("Mail: student@example.org; SSN: 123-45-6789; Bank account: 12345678901234; "
                "IFSC: ABCD0123456; IBAN: GB82 WEST 1234 5698 7654 32; "
                "Credit card: 4111 1111 1111 1111; PAN: ABCPA1234Z; Passport: A1234567; "
                "UPI ID: demo@bank; Password: demo-Secret42; API key: demo_key_12345678; "
                "Bearer sample_token_12345678; Postal code: SW1A 1AA; Home address: 18 Oak Road; 25 Cedar Street")
        report = privacy_detector.privacy_report(text)
        kinds = {k for k, n in report["counts"].items() if n}
        self.assertEqual(kinds, set(privacy_detector.PLACEHOLDERS) - {"phone_numbers", "aadhaar_numbers"})
        self.assertEqual(len(report["review"]), 1)
        hit = report["review"][0]
        self.assertEqual(text[hit["start"]:hit["end"]], "25 Cedar Street")
        checked = privacy_detector.privacy_report(text, [hit["id"]])
        self.assertEqual(checked["total_redacted"], report["total_redacted"] + 1)
        self.assertTrue(checked["redacted_text"].endswith("[ADDRESS]"))

    def test_repeated_and_adjacent_values_keep_original_formatting(self):
        original = "First: name@example.org\nAgain: name@example.org\nOrder: AX1234567890"
        result = privacy_detector.privacy_report(original)
        self.assertEqual(result["redacted_text"], "First: [EMAIL]\nAgain: [EMAIL]\nOrder: AX1234567890")
        self.assertEqual(result["counts"]["emails"], 2)

    def test_quoted_passphrases_are_redacted_as_one_span(self):
        self.assertEqual(privacy_detector.redact_private_info('Passphrase: "Demo sample phrase 42".'),
                         'Passphrase: "[PASSWORD]".')

    def test_postal_formats_and_iban_leave_adjacent_prose_intact(self):
        report = privacy_detector.privacy_report(
            "📫 IBAN number: GB82 WEST 1234 5698 7654 32 for the invoice.\n"
            "Postcode: 100-0001. PIN code: 110001. ZIP: 20001-0100."
        )
        self.assertEqual(report["redacted_text"], "📫 IBAN number: [IBAN] for the invoice.\n"
                         "Postcode: [POSTAL CODE]. PIN code: [POSTAL CODE]. ZIP: [POSTAL CODE].")
        self.assertEqual(report["offset_encoding"], "unicode_code_points")
        self.assertEqual(report["redactions"][0]["start"], 15)
        self.assertEqual(report["counts"]["postal_codes"], 3)

    def test_indian_number_context_and_review_are_distinct(self):
        text = "Text me at 9876543210\nOrder reference ID: 9876543210\n9876543210\n2026-11-24 13:15:09"
        report = privacy_detector.privacy_report(text)
        self.assertEqual(report["counts"]["phone_numbers"], 1)
        self.assertEqual(report["total_review"], 1)
        hit = report["review"][0]
        self.assertEqual(hit["start"], text.rfind("9876543210"))
        self.assertEqual(privacy_detector.privacy_report(text, [hit["id"]])["total_redacted"], 2)

    @unittest.skipUnless(privacy_detector.usaddress is not None, "offline US address parser is not installed")
    def test_structured_addresses_and_unrelated_lines(self):
        report = privacy_detector.privacy_report(
            "Please ship to:\n123 Example St Apt 4, Washington, DC 20001.\nThank you."
        )
        self.assertEqual(report["redacted_text"], "Please ship to:\n[ADDRESS].\nThank you.")

    @unittest.skipUnless(privacy_detector.usaddress, "local address parser is unavailable")
    def test_multiline_address_and_invalid_identifier_reviews(self):
        base = "23456789012"
        valid = base + verhoeff.calc_check_digit(base)
        invalid = valid[:-1] + str((int(valid[-1]) + 1) % 10)
        text = ("Address:\n123 Example St Apt 4\nWashington, DC 20001\n\n"
                f"Aadhaar: {invalid}\nTracking: {valid}\n"
                "Debit card: 4111 1111 1111 1112\nInvoice: 9876543210\nUnrelated: 20001")
        report = privacy_detector.privacy_report(text)
        self.assertEqual(report["redacted_text"], text.replace(
            "123 Example St Apt 4\nWashington, DC 20001", "[ADDRESS]"))
        invalid_hit, = report["review"]
        self.assertEqual(invalid_hit["category"], "aadhaar_numbers")
        self.assertEqual(report["findings"][-1]["validation"], "invalid_format_or_checksum")

    def test_labelled_phone_and_bank_have_distinct_context(self):
        text = ("Bank account: 9876543210\nInvoice ID: 9876543210\n"
                "WhatsApp: +91 9123456789\nTelephone: +1 202-555-0101")
        result = privacy_detector.privacy_report(text)
        self.assertEqual(result["counts"]["bank_accounts"], 1)
        self.assertEqual(result["counts"]["phone_numbers"], 2)
        self.assertIn("Invoice ID: 9876543210", result["redacted_text"])


class AssessmentTests(unittest.TestCase):
    def test_conversations_and_privacy_do_not_issue_phishing_alerts(self):
        for message in (
            "Hello", "How are you doing?", "Hey man how are you doing i am doing well how about you",
            "How are you doing today", "Hey how are you what are you doing",
            "Never share your password or OTP with anyone", "Please send me the homework when you finish",
            "I has completed my homework yesterday", "Here is the Python documentation: https://docs.python.org/3/",
            "The class meeting is tomorrow in the library. Email student@example.org for the agenda.",
            "We will never ask you to send your password in an email. Contact your help desk if unsure.",
            "Confirm your password reset in your account's security history.",
        ):
            with self.subTest(message=message):
                result = server.predict_email_risk(message)
                self.assertNotEqual(result["risk_level"], "suspicious")
                if result["safety_score"] is not None:
                    self.assertAlmostEqual(result["risk_score"] + result["safety_score"], 100)

    def test_subject_sender_link_and_grammar_evidence(self):
        result = server.predict_email_risk(
            "Please send your password to re-enable access. Your account have been suspended.",
            sender="PayPal Support <nobody@example.net>", reply_to="reply@example.org",
            subject="Final notice: verify your account",
            html='<a href="https://example.net/login?session=secret">https://paypal.com/login</a>',
            links=["https://example.net/login?session=secret"],
        )
        self.assertEqual(result["assessment"], "Suspicious")
        self.assertEqual(result["sender"]["authentication"], "unavailable")
        self.assertEqual(len(result["links"]), 1)
        self.assertNotIn("session=secret", json.dumps(result["links"]))
        self.assertIn(result["links"][0]["model_observation"]["status"], {"flagged", "not_flagged"})
        self.assertEqual(result["links"][0]["assessment"], "Suspicious")
        self.assertTrue(any(m["category"] == "subject" for m in result["markers"]))
        self.assertTrue(any(m["category"] == "sender" for m in result["markers"]))
        self.assertEqual(result["grammar"]["issues"][0]["suggestion"], "has")

    def test_subject_authentication_is_unavailable_and_sender_lookalike_is_explained(self):
        result = server.predict_email_risk("There was an activity notice. Open your account directly for details.",
                                           sender="PayPal Support <notify@paypаl.com>", subject="Security alert")
        self.assertEqual(result["assessment"], "Caution advised")
        self.assertIn("security_notice_subject", {marker["id"] for marker in result["subject_findings"]})
        self.assertIn("sender_lookalike", {marker["id"] for marker in result["markers"]})
        self.assertEqual(result["sender"]["authentication"], "unavailable")

    def test_pressure_and_an_ordinary_link_are_insufficient(self):
        result = server.predict_email_risk(
            "Verify your account at https://example.org/settings. Contact support if you need assistance.",
            subject="Account has been suspended",
        )
        self.assertNotEqual(result["display_level"], "danger")
        self.assertEqual(len(result["links"]), 1)

    def test_reports_credential_requests_without_using_grammar_or_brand_words_as_verdict(self):
        result = server.predict_email_risk("Please reply with the verification code sent to your device.")
        self.assertEqual(result["risk_level"], "suspicious")
        self.assertEqual(result["markers"][0]["excerpt"], "reply with the verification code")
        self.assertEqual(result["grammar"]["count"], 0)

    def test_writing_findings_are_separate(self):
        a = writing_checks("Your account have been changed!!! See teh update.")
        b = writing_checks("Your account has been changed. See the update.")
        self.assertGreater(a["count"], 0)
        self.assertEqual(b["count"], 0)
        self.assertNotEqual(server.predict_email_risk("Teh teh teh!!!")["risk_level"], "suspicious")

    def test_optional_grammar_uses_only_loopback_and_preserves_offsets(self):
        with patch.dict(os.environ, SENTINELAI_LANGUAGETOOL_PORT="8081"), patch("backend.assessments.requests.Session") as session:
            client = session.return_value.__enter__.return_value
            response = client.post.return_value.__enter__.return_value
            response.status_code = 200
            response.iter_content.return_value = [json.dumps({"matches": [{"offset": 3, "length": 3,
                "message": "Possible misspelling", "replacements": [{"value": "the"}]}]}).encode()]
            result = writing_checks("🙂 teh exam. https://example.org\nPassword: sample-only-pass")
            self.assertEqual(result["issues"][0]["excerpt"], "teh")
            self.assertEqual(result["status"], "local_languagetool")
            self.assertFalse(client.trust_env)
            self.assertEqual(client.post.call_args.args, ("http://127.0.0.1:8081/v2/check",))
            self.assertFalse(client.post.call_args.kwargs["allow_redirects"])
            self.assertNotIn("example.org", client.post.call_args.kwargs["data"]["text"])
            self.assertNotIn("sample-only-pass", client.post.call_args.kwargs["data"]["text"])
            response.status_code = 503
            self.assertEqual(writing_checks("Teh exam.")["status"], "limited_local_english")

    def test_url_does_not_infer_safety_from_brand_or_transport(self):
        for url in ("https://www.amazon.in/s?k=books", "https://www.flipkart.com/",
                    "https://www.youtube.com/results?q=a", "http://example.org"):
            with self.subTest(url=url):
                response = server.predict_url_risk(url)
                self.assertNotEqual(response["display_level"], "danger")
                self.assertTrue(0 <= response["risk_score"] <= 100)
                self.assertAlmostEqual(response["risk_score"] + response["safety_score"], 100)
        self.assertEqual(server.predict_url_risk("https://example.org@example.net/")["risk_level"], "suspicious")

    def test_page_signals_need_context(self):
        observations = dict.fromkeys(PAGE_FEATURES, 0) | {"overlays": 1, "blocking_overlay": 1}
        self.assertEqual(webpage_evidence("https://example.org", observations)["risk_level"], "neutral")
        observations.update({"infection_claim": 1, "support_request": 1})
        self.assertEqual(webpage_evidence("https://example.org", observations)["risk_level"], "suspicious")
        with self.assertRaises(ValueError):
            webpage_evidence("https://example.org", {**observations, "password": 5})
        independent_forms = dict.fromkeys(PAGE_FEATURES, 0) | {"credential_forms": 1, "external_forms": 1}
        self.assertEqual(webpage_evidence("https://example.org", independent_forms)["risk_level"], "neutral")
        combined = independent_forms | {"external_credential_forms": 1, "browser_impersonation": 1}
        self.assertEqual(webpage_evidence("https://example.org", combined)["risk_level"], "suspicious")
        with self.assertRaises(ValueError):
            webpage_evidence("https://example.org", combined | {"external_credential_forms": 2})

    def test_model_only_scores_do_not_issue_authoritative_alerts(self):
        with patch("backend.server.url_model_observations", return_value=[
            {"status": "flagged", "phishing_probability": .99, "prediction": "phishing"}
        ]):
            result = server.predict_url_risk("https://example.org")
            self.assertEqual(result["model_observation"]["status"], "flagged")
            self.assertGreater(result["risk_score"], 0)
            self.assertEqual(result["display_level"], "suspicious")
            self.assertEqual(result["assessment"], "Caution advised")

    def test_missing_model_and_different_inputs(self):
        with patch("backend.server.email_model", return_value=None):
            result = server.predict_email_risk("Let us meet at the library after school. Please bring the homework.")
            self.assertIsNone(result["safety_score"])
            self.assertEqual(result["assessment"], "Analysis unavailable")
        legitimate = server.predict_email_risk("Let us meet at the library after school. Please bring the homework.")
        phishing = server.predict_email_risk("Please reply with your password.")
        self.assertLess(legitimate["risk_score"], phishing["risk_score"])
        self.assertGreater(phishing["risk_score"], 58)


class StorageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Path(directory.name) / "application.db"
        self.threat_db = Path(directory.name) / "threats.db"
        env = patch.dict(os.environ, SENTINELAI_DB_PATH=str(self.db), SENTINELAI_THREATS_PATH=str(self.threat_db))
        env.start()
        self.addCleanup(env.stop)
        self.handler = object.__new__(server.SentinelAPIHandler)
        self.handler.headers = {"Host": "127.0.0.1:8000"}
        self.handler.command = "POST"
        server.init_db()

    def test_api_consent_review_export_and_storage(self):
        call = self.handler.handle_post
        payload = {"text": "Send your password now. Address demo@example.org.", "collect_sample": True}
        self.assertIsNone(call("/api/scan-email", payload)["sample_id"])
        call("/api/threats/settings", {"enabled": True})
        self.assertNotIn("sample_id", call("/api/scan-email", {**payload, "collect_sample": False}))
        sample_id = call("/api/scan-email", payload)["sample_id"]
        self.assertIsInstance(sample_id, int)
        self.assertIsNone(call("/api/scan-email", payload)["sample_id"])
        self.assertEqual(server.threats.list_samples()["counts"], {"pending": 1})
        self.assertEqual(server.threats.list_samples(approved_only=True), [])
        with self.assertRaises(ValueError):
            call("/api/threats/review", {"id": sample_id, "action": "approve"})
        call("/api/threats/review", {"id": sample_id, "action": "legitimate"})
        call("/api/threats/review", {"id": sample_id, "action": "approve"})
        row = server.threats.list_samples(approved_only=True)[0]
        self.assertEqual(row["label"], "legitimate")
        call("/api/threats/review", {"id": sample_id, "action": "phishing"})
        self.assertEqual(server.threats.list_samples(approved_only=True), [])

        call("/api/scan-url", {"url": "https://example.org/?token=demo-test-secret", "collect_sample": True})
        call("/api/privacy-redact", {"text": "Email: demo@example.org", "context": "do-not-save-raw"})
        for path in (self.db, self.threat_db):
            db = sqlite3.connect(path)
            self.addCleanup(db.close)
            dump = "\n".join(db.iterdump())
            for secret in ("demo@example.org", "do-not-save-raw", "demo-test-secret", "Send your password"):
                self.assertNotIn(secret, dump)
        self.assertEqual(server.get_stats()["items_redacted"], 1)

    def test_old_history_kept_but_raw_preview_not_returned(self):
        db = sqlite3.connect(self.db)
        with db:
            db.execute("DROP TABLE scan_history")
            db.execute(SCAN_SCHEMA.replace("confidence REAL,", "confidence REAL NOT NULL,"))
            db.execute("INSERT INTO scan_history (scan_type,target_preview,risk_level,confidence) VALUES ('email','original text','safe',0.92)")
        db.close()
        server.init_db()
        row = server.get_recent_history()[0]
        self.assertTrue(row["legacy"])
        self.assertNotIn("original text", json.dumps(row))
        server.log_scan("email", "new private preview", "uncertain", None, [])
        with sqlite3.connect(self.db) as db:
            previews = db.execute("SELECT target_preview FROM scan_history ORDER BY id").fetchall()
            self.assertEqual(previews, [("original text",), ("Email assessment",)])

    def test_retention_is_explicit_and_keeps_recent_samples(self):
        server.threats.settings(True, 7)
        old = server.threats.collect("url", {"path_length": 5}, "uncertain", True)
        recent = server.threats.collect("url", {"path_length": 7}, "neutral", True)
        with sqlite3.connect(self.threat_db) as db:
            db.execute("UPDATE samples SET created_at = '2000-01-01' WHERE id = ?", (old,))
        self.assertEqual(len(server.threats.list_samples()["samples"]), 2)
        self.assertEqual(server.threats.prune(), 1)
        self.assertEqual([row["id"] for row in server.threats.list_samples()["samples"]], [recent])

    def test_text_export_requires_separate_consent_and_human_approval(self):
        call = self.handler.handle_post
        body = ("Please send a security report about the account. From fixture@example.org. "
                "Password: fixture-hidden-secret. Link: https://example.org/private?token=fixture-query-secret")
        message = {"text": body, "subject": "Meeting reminder for Taylor", "collect_sample": True, "collect_text": True}
        call("/api/threats/settings", {"enabled": True})
        numeric = call("/api/v2/scan-email", message)["sample_id"]
        self.assertIsNone(server.threats.list_samples()["samples"][0]["sanitized_body"])
        call("/api/threats/settings", {"sanitized_text_enabled": True})
        self.assertIsNone(call("/api/v2/scan-email", message | {"collect_text": False})["sample_id"])
        sample = call("/api/v2/scan-email", message)["sample_id"]
        self.assertNotEqual(sample, numeric)
        self.assertEqual(server.threats.list_samples(approved_only=True, mode="text"), [])
        call("/api/threats/review", {"id": sample, "action": "legitimate"})
        call("/api/threats/review", {"id": sample, "action": "approve"})
        exported, = server.threats.list_samples(approved_only=True, mode="text")
        self.assertEqual(exported["subject"], "meeting reminder")
        self.assertIn("security", exported["body"])
        with sqlite3.connect(self.threat_db) as db:
            dump = "\n".join(db.iterdump())
        for private in ("fixture@example.org", "fixture-hidden-secret", "fixture-query-secret", "Taylor", "example.org"):
            self.assertNotIn(private, dump)
        call("/api/threats/review", {"id": sample, "action": "delete"})
        self.assertEqual(server.threats.list_samples(approved_only=True, mode="text"), [])
        with sqlite3.connect(self.threat_db) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM sanitized_samples").fetchone()[0], 0)

    def test_legacy_payloads_use_neutral_unknown_state_and_all_privacy_categories(self):
        call = self.handler.handle_post
        short = call("/api/scan-email", {"text": "Hello", "preview": True})
        self.assertEqual(short["assessment"], "Insufficient information")
        self.assertEqual(short["evidence_level"], "uncertain")
        self.assertEqual(short["risk_level"], "unknown")
        self.assertIsNone(short["safety_score"])
        self.assertEqual(call("/api/v2/scan-email", {"text": "Hello", "preview": True})["risk_level"], "uncertain")
        expanded = call("/api/scan-email", {"text": "IBAN: GB82 WEST 1234 5698 7654 32", "preview": True})
        self.assertEqual(expanded["private_items_count"], 1)
        self.assertEqual(expanded["privacy_counts"]["iban_numbers"], 1)
        self.assertEqual(server.get_stats()["total_scans"], 0)
        self.handler.headers["Origin"] = "https://mail.google.com"
        overlay = call("/api/scan-email", {"text": "Send your password. demo@example.org", "collect_sample": True})
        self.assertEqual(overlay["risk_level"], "danger")
        self.assertNotIn("demo@example.org", json.dumps(overlay))
        self.assertNotIn("sample_id", overlay)

    def test_compose_preview_masks_only_metadata_and_selected_audit_counts(self):
        call = self.handler.handle_post
        body = "✨ Email: demo@example.org\nEmail: demo@example.org\nAadhaar: 2345-6789-0120"
        data = call("/api/privacy-redact", {"text": body, "preview": True, "findings_only": True})
        self.assertEqual(set(data), {"findings", "offset_encoding"})
        self.assertNotIn("demo@example.org", json.dumps(data))
        emails = [item for item in data["findings"] if item["category"] == "emails"]
        self.assertEqual(len(emails), 2)
        redacted = call("/api/privacy-redact", {"text": body, "selected": [emails[1]["id"]], "context": "gmail_compose"})
        self.assertEqual(redacted["redacted_text"], body.replace("\nEmail: demo@example.org", "\nEmail: [EMAIL]"))
        self.assertEqual(server.get_stats()["items_redacted"], 1)

    def test_browser_origin_is_restricted(self):
        self.handler.headers["Origin"] = "https://example.org"
        self.assertFalse(self.handler.allowed("/api/scan-email"))
        self.handler.headers["Origin"] = "https://mail.google.com"
        self.assertTrue(self.handler.allowed("/api/scan-email"))
        self.assertFalse(self.handler.allowed("/api/threats/export"))
        self.handler.command = "GET"
        self.assertFalse(self.handler.allowed("/api/scan-email"))
        self.handler.command = "OPTIONS"
        self.handler.headers["Access-Control-Request-Method"] = "POST"
        self.assertTrue(self.handler.allowed("/api/scan-email"))
        self.handler.headers["Host"] = "nonlocal.example"
        self.assertFalse(self.handler.allowed("/api/scan-email"))


class TrainingTests(unittest.TestCase):
    def test_numeric_import_rejects_confirmed_but_unapproved_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.json"
            row = {"kind": "url", "version": "features-v1", "label": "legitimate",
                   "features": {"URLLength": 20}}
            path.write_text(json.dumps([row | {"status": "confirmed_legitimate"}]))
            with self.assertRaises(ValueError):
                read_features(path, "url", approved=True)
            path.write_text(json.dumps([row | {"status": "approved"}]))
            self.assertEqual(read_features(path, "url", approved=True), [({"URLLength": 20}, 0, "")])

    def test_approved_masked_email_can_train_with_an_independent_holdout(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            path = output / "export.json"
            row = {"kind": "email", "version": "masked-terms-v1", "label": "phishing",
                   "subject": "security alert", "body": "send password immediately", "status": "approved"}
            path.write_text(json.dumps({"samples": [row]}))
            fit = read_masked_email(path, approved=True)
            self.assertEqual(fit, [("security alert send password immediately", 1, "")])
            fit.append(("school meeting schedule attendance", 0, "fit"))
            holdout = [("school homework lesson", 0, "independent"), ("verify account password", 1, "independent")]
            report = train("email", fit, holdout, output / "candidate", text=True)
            self.assertEqual(report["feature_version"], "masked-terms-v1")
            path.write_text(json.dumps([row | {"body": "password nonallowlisted-fixture"}]))
            with self.assertRaises(ValueError):
                read_masked_email(path, approved=True)

    def test_candidate_stays_separate_and_conflicting_labels_fail(self):
        fit = [({"features": n}, label, "fit") for n, label in [(0, 0), (1, 0), (9, 1), (10, 1)]]
        test = [({"features": 3}, 0, "holdout"), ({"features": 7}, 1, "holdout")]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "candidate"
            report = train("webpage", fit, test, output)
            self.assertTrue((output / "webpage_candidate.joblib").is_file())
            self.assertEqual(sum(sum(row) for row in report["candidate"]["confusion"]), 2)
            with self.assertRaises(ValueError):
                train("webpage", fit + [({"features": 0}, 1, "fit")], test, Path(directory) / "conflict")
            with self.assertRaises(ValueError):
                train("webpage", fit, [({"features": 3}, 0, "fit"), test[1]], Path(directory) / "overlap")


if __name__ == "__main__":
    unittest.main()
