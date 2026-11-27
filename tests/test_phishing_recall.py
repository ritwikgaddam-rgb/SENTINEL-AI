"""Regression fixtures for the deployed email alert contract."""
import unittest

import numpy as np

from backend import server
from training.email_recall_study import (
    CalibratedStackingClassifier, Mail, audit_current_errors, choose_oof_threshold,
    choose_threshold, domain_lexical_risk, extract_domain_agnostic_features,
    extract_linkless_social_engineering_features, extract_privacy_safe_features,
    extract_sender_display_features, extract_structural_link_features,
    levenshtein_similarity, make_dense_semantic_pipeline, make_partitions
)

BENIGN = (
    "Hello.",
    "How are you doing today?",
    "Hey how are you what are you doing.",
    "Please send me the homework when you finish.",
    "Never share your password or OTP with anyone.",
    "I has completed my homework yesterday.",
    "Here is the Python documentation: https://docs.python.org/3/",
    "The science club meets in the library after school. Bring a notebook.",
    "The draft budget is ready. Could you check the totals before our meeting?",
    "For your safety, don't give anyone your verification code. Open your usual app to review the alert.",
)


class EmailAlertRegressionTests(unittest.TestCase):
    def test_benign_messages_remain_free_of_alerts(self):
        for body in BENIGN:
            with self.subTest(body=body):
                result = server.predict_email_risk(body)
                self.assertTrue(result["ml_evaluated"])
                self.assertIn(result["display_level"], {"safe", "unknown"})
                if result["display_level"] == "unknown":
                    self.assertIsNone(result["safety_score"])

    def test_original_model_and_structural_evidence_have_separate_outputs(self):
        result = server.predict_email_risk(
            "Please reply with your password to confirm the account.",
            "Example Support <notices@example.org>",
            [{"url": "https://example.net/review", "label": "https://example.org/review"}],
            subject="Final notice to verify your account", reply_to="audit@example.net",
        )
        self.assertEqual(result["display_level"], "danger")
        self.assertTrue(result["ml_evaluated"])
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)
        self.assertAlmostEqual(result["risk_score"] + result["safety_score"], 100)
        self.assertTrue({"credential_request", "reply_domain_mismatch", "link_deception"}
                        <= {m["id"] for m in result["markers"]})
        self.assertEqual(result["links"][0]["assessment"], "Suspicious")
        self.assertEqual(server.legacy_scan_response(result)["risk_level"], result["display_level"])


class EmailEvaluationTests(unittest.TestCase):
    def test_guard_maximum_can_be_the_only_useful_cutoff(self):
        labels = np.array([0, 0, 1, 1])
        scores = np.array([0.12, 0.26, 0.46, 0.93])
        guard = np.array([0.25, 0.81])
        for choose in (choose_oof_threshold, choose_threshold):
            with self.subTest(selector=choose.__name__):
                threshold = choose(labels, scores, guard)
                self.assertEqual(threshold, max(guard))
                np.testing.assert_array_equal(scores > threshold, [False, False, False, True])
                self.assertFalse((guard > threshold).any())

    def test_threshold_respects_false_positive_budget_and_short_mail(self):
        labels = np.array([0] * 20 + [1, 1, 1])
        scores = np.array([0.1] * 18 + [0.5, 0.8, 0.4, 0.9, 0.95])
        self.assertEqual(choose_threshold(labels, scores, np.array([0.55])), 0.8)

    def test_related_holdout_template_is_removed_from_training(self):
        template = "We have reserved the small meeting room for our training event"
        holdout = Mail(template + " on Monday morning.", 0, "held out")
        relative = Mail(template + " on Wednesday afternoon.", 0, "fit")
        unique = Mail("Your student council vote was counted.", 0, "fit")
        rows, counts = make_partitions({"fit": [relative, unique], "validation": [],
                                        "manual": [holdout], "real": []})
        self.assertEqual([mail for mail, _ in rows["fit"]], [unique])
        self.assertEqual([mail for mail, _ in rows["manual"]], [holdout])
        self.assertEqual(counts["fit"]["cross_partition_template"], 1)


class StructuralFeatureAndRecallTests(unittest.TestCase):
    def test_anchor_to_url_domain_mismatch_detected(self):
        deceptive_links = [
            {"url": "https://evil-phish.com/login", "label": "https://paypal.com/signin"},
        ]
        feats = extract_structural_link_features(deceptive_links)
        self.assertEqual(feats["anchor_url_mismatch"], 1)
        self.assertEqual(feats["total_links"], 1)

        brand_deceptive = [
            {"url": "https://account-update-portal.info/auth", "label": "Log in to your PayPal account"},
        ]
        feats_brand = extract_structural_link_features(brand_deceptive)
        self.assertEqual(feats_brand["anchor_url_mismatch"], 1)

        legit_links = [
            {"url": "https://paypal.com/signin", "label": "https://paypal.com/account"},
        ]
        feats_legit = extract_structural_link_features(legit_links)
        self.assertEqual(feats_legit["anchor_url_mismatch"], 0)

    def test_known_esp_click_tracker_safelisting(self):
        esp_links = [
            {"url": "https://ct.sendgrid.net/ls/click?upn=abc123xyz", "label": "Manage notification preferences"},
            {"url": "https://mailchimp.com/track/click?user=123", "label": "View your monthly invoice"},
            {"url": "https://awstrack.me/L0/https:%2F%2Fexample.com", "label": "Order details"},
        ]
        feats = extract_structural_link_features(esp_links)
        self.assertEqual(feats["is_esp_safelisted"], 1)
        # ESP click trackers must NOT be flagged as open redirect attacks or anchor mismatches
        self.assertEqual(feats["has_open_redirect"], 0)
        self.assertEqual(feats["anchor_url_mismatch"], 0)

    def test_url_obfuscation_signals(self):
        raw_ip_link = [{"url": "http://192.168.1.100/verify", "label": "Verify account"}]
        self.assertEqual(extract_structural_link_features(raw_ip_link)["has_raw_ip"], 1)

        punycode_link = [{"url": "https://xn--pple-43d.com/login", "label": "Apple ID"}]
        self.assertEqual(extract_structural_link_features(punycode_link)["has_punycode"], 1)

        deep_subdomain = [{"url": "https://login.security.account.verify.evil.com/auth", "label": "Sign in"}]
        self.assertEqual(extract_structural_link_features(deep_subdomain)["has_deep_subdomain"], 1)

        tunnel_host = [{"url": "https://secure-login.pages.dev/token", "label": "Document"}]
        self.assertEqual(extract_structural_link_features(tunnel_host)["has_tunnel_host"], 1)

        open_redirect = [{"url": "https://example.org/redirect?url=https://phish.com", "label": "Continue"}]
        self.assertEqual(extract_structural_link_features(open_redirect)["has_open_redirect"], 1)

    def test_display_name_and_sender_mismatch(self):
        spoofed = extract_sender_display_features("PayPal Security <urgent.notices29@gmail.com>")
        self.assertEqual(spoofed["display_brand_mismatch"], 1)
        self.assertEqual(spoofed["sender_is_freemail"], 1)

        legit_brand = extract_sender_display_features("PayPal Support <support@paypal.com>")
        self.assertEqual(legit_brand["display_brand_mismatch"], 0)
        self.assertEqual(legit_brand["sender_is_freemail"], 0)

        personal_freemail = extract_sender_display_features("Alice Smith <alice@gmail.com>")
        self.assertEqual(personal_freemail["display_brand_mismatch"], 0)
        self.assertEqual(personal_freemail["sender_is_freemail"], 1)

        reply_to_diff = extract_sender_display_features("Service <noreply@corp.com>", reply_to="attacker@gmail.com")
        self.assertEqual(reply_to_diff["reply_to_mismatch"], 1)

    def test_oof_threshold_bounds_respect_target_fpr(self):
        # 40 benign messages (label 0), 10 phishing messages (label 1)
        labels = np.array([0] * 40 + [1] * 10)
        # OOF probabilities: negatives mostly low, 1 moderate (0.3), 1 high (0.8)
        # Positives mostly high
        oof_probs = np.array([0.05] * 38 + [0.3, 0.8] + [0.4, 0.6, 0.7, 0.85, 0.9, 0.92, 0.95, 0.96, 0.98, 0.99])
        ham_probs = np.array([0.1, 0.15, 0.25])

        # Target FPR <= 2.5% (meaning at most 1 / 40 = 2.5% false positives)
        threshold = choose_oof_threshold(labels, oof_probs, ham_probs, target_fpr=0.025)
        self.assertGreaterEqual(threshold, 0.3)
        self.assertGreater(threshold, np.max(ham_probs))

        alerts = oof_probs > threshold
        realized_fpr = np.mean(alerts[labels == 0])
        self.assertLessEqual(realized_fpr, 0.025)

    def test_audit_current_errors_slicing(self):
        mail_0 = Mail("No links security advice", 0, "test", sender="security@corp.com", links=())
        mail_1 = Mail("With link transactional", 0, "test", sender="receipts@sendgrid.net",
                      links=({"url": "https://ct.sendgrid.net/click", "label": "Receipt"},))
        mail_2 = Mail("Phishing credential harvest", 1, "test", sender="PayPal <bad@gmail.com>",
                      links=({"url": "https://evil.com", "label": "Login"},))

        rows = [mail_0, mail_1, mail_2]
        labels = np.array([0, 0, 1])
        # Simulate an FP on mail_0 and an FN on mail_2
        predictions = np.array([1, 0, 0])
        probs = np.array([0.65, 0.10, 0.40])

        audit = audit_current_errors(labels, predictions, rows, probs)
        self.assertEqual(audit["total_evaluated"], 3)
        self.assertEqual(audit["false_positives"]["count"], 1)
        self.assertEqual(audit["false_positives"]["by_links"]["0_links"], 1)
        self.assertEqual(audit["false_negatives"]["count"], 1)
        self.assertEqual(audit["false_negatives"]["by_sender"]["freemail"], 1)

    def test_sender_vs_href_mismatch_and_free_webmail_cta(self):
        links = [{"url": "https://secure-invoice-portal.net/auth", "label": "View Document"}]
        sender = "Accounting Dept <billing.dept29@gmail.com>"
        feats = extract_domain_agnostic_features(sender=sender, links=links, body="Please view the document.")
        self.assertEqual(feats["sender_vs_href_mismatch"], 1)
        self.assertEqual(feats["free_webmail_with_external_cta"], 1)
        self.assertEqual(feats["has_action_anchor"], 1)
        self.assertGreater(feats["link_density"], 0)

        # Same domain matches without mismatch
        legit_sender = "Support <support@mycorp.com>"
        legit_links = [{"url": "https://mycorp.com/billing", "label": "Review Invoice"}]
        legit_feats = extract_domain_agnostic_features(sender=legit_sender, links=legit_links)
        self.assertEqual(legit_feats["sender_vs_href_mismatch"], 0)
        self.assertEqual(legit_feats["free_webmail_with_external_cta"], 0)

    def test_typosquatting_and_lexical_risk(self):
        self.assertGreaterEqual(levenshtein_similarity("micros0ft.com", "microsoft.com"), 0.82)
        self.assertGreaterEqual(levenshtein_similarity("paypa1.com", "paypal.com"), 0.82)
        self.assertGreaterEqual(levenshtein_similarity("arnazon.com", "amazon.com"), 0.81)

        typo_risk = domain_lexical_risk("micros0ft.com")
        self.assertEqual(typo_risk["is_typosquat"], 1)
        self.assertGreater(typo_risk["max_target_sim"], 0.82)

        tld_risk = domain_lexical_risk("account-verify.xyz")
        self.assertEqual(tld_risk["high_risk_tld"], 1)
        self.assertGreater(tld_risk["hyphen_count"], 0)

        normal_risk = domain_lexical_risk("normaluniversity.edu")
        self.assertEqual(normal_risk["is_typosquat"], 0)
        self.assertEqual(normal_risk["high_risk_tld"], 0)

    def test_linkless_social_engineering_signals(self):
        callback_phish = "Your Geek Squad subscription charged $499. Call toll-free 1-800-555-0199 to cancel."
        feats_cb = extract_linkless_social_engineering_features(body=callback_phish, links=())
        self.assertEqual(feats_cb["callback_phishing_signal"], 1)
        self.assertEqual(feats_cb["regime_no_links"], 1)

        wire_phish = "URGENT: Please process a same-day wire transfer to the updated bank details."
        feats_wire = extract_linkless_social_engineering_features(body=wire_phish, links=())
        self.assertEqual(feats_wire["wire_urgency_signal"], 1)

        attachment_phish = "Please find the attached invoice statement for your review."
        feats_att = extract_linkless_social_engineering_features(body=attachment_phish, links=())
        self.assertEqual(feats_att["attachment_lure_signal"], 1)

        benign_advice = "Never share your password or OTP with anyone. Keep it private."
        feats_benign = extract_linkless_social_engineering_features(body=benign_advice, links=())
        self.assertEqual(feats_benign["callback_phishing_signal"], 0)
        self.assertEqual(feats_benign["wire_urgency_signal"], 0)

    def test_dense_semantic_pipeline_and_stacking(self):
        pipe = make_dense_semantic_pipeline(n_components=5)
        texts = [
            "Urgent payment required for your account invoice",
            "Verify your credentials and login password immediately",
            "Hey how are you doing see you at the library",
            "The science project draft is attached for homework",
        ]
        labels = [1, 1, 0, 0]
        pipe.fit(texts, labels)
        probs = pipe.predict_proba(texts)[:, 1]
        self.assertEqual(len(probs), 4)
        self.assertGreater(probs[0], probs[2])

        rows = [Mail(t, l, "unit_test") for t, l in zip(texts, labels)]
        stacker = CalibratedStackingClassifier(dense_text_pipeline=pipe)
        with self.assertRaisesRegex(ValueError, "Both fit and validation"):
            stacker.fit_and_tune_oof(rows[:2], labels[:2], rows[2:], labels[2:], n_splits=2)
        examples = [Mail(chr(97 + i // 26) + chr(97 + i % 26) + " " + texts[i % 4],
                         labels[i % 4], "fixture") for i in range(64)]
        stacker.fit_and_tune_oof(examples[:40], [r.label for r in examples[:40]],
                                 examples[40:], [r.label for r in examples[40:]], n_splits=2)
        self.assertEqual(stacker.predict(rows).shape, (4,))

    def test_tracker_does_not_override_an_explicit_destination_mismatch(self):
        features = extract_structural_link_features([{"url": "https://ct.sendgrid.net/path",
                                                     "label": "https://example.org/path"}])
        self.assertEqual(features["anchor_url_mismatch"], 1)
