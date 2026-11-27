"""Exercise research features using synthetic mail and inert link text."""

import unittest

import numpy as np

from training.email_recall_study import Mail
from training.gemini_features import (
    compute_deconfounded_sample_weights,
    compute_prototype_margin,
    extract_benign_suppressor_features,
    extract_lots_and_url_lure_features,
    extract_sparse_header_short_features,
    two_view_texts,
)


class GeminiFeatureTests(unittest.TestCase):
    def test_source_weights_reserve_modern_bonus_for_benign_fit_rows(self):
        rows = [
            Mail("The team meets at nine.", 0, "20030228_easy_ham.tar.bz2"),
            Mail("Thanks for your order. The order total appears below.", 0, "Solidus strings"),
            Mail("Thanks for your order. The order total appears below.", 1, "archive"),
            Mail("The deadline is Friday.", 0, "other"),
        ]
        weights = compute_deconfounded_sample_weights(rows)
        self.assertAlmostEqual(weights.mean(), 1)
        np.testing.assert_allclose(weights / weights[-1], [0.6, 3.0, 1, 1])
        np.testing.assert_array_equal(compute_deconfounded_sample_weights(rows, 1, 1), np.ones(4))

    def test_shared_host_needs_action_and_tracking_link_earns_no_trust(self):
        shared = "https://forms.office.com/example"
        ordinary = Mail(
            "Here are the notes from history class.", 0, "test", links=({"url": shared, "label": "Notes"},)
        )
        call_to_action = Mail(
            "Please sign in to view document.", 1, "test", links=({"url": shared, "label": "Sign in"},)
        )
        self.assertEqual(extract_lots_and_url_lure_features(ordinary)["abused_cloud_host_with_cta"], 0)
        self.assertEqual(extract_lots_and_url_lure_features(call_to_action)["abused_cloud_host_with_cta"], 1)
        tracker = Mail("Here is our newsletter.", 0, "test", links=("https://ct.sendgrid.net/example",))
        features = extract_lots_and_url_lure_features(tracker)
        self.assertEqual(features["tracking_link_observed"], 1)
        self.assertEqual(features["credential_path_lure"], 0)
        self.assertEqual(
            extract_lots_and_url_lure_features(
                Mail(
                    "See the website mentioned in class.",
                    0,
                    "test",
                    links=("https://local.example/auth?receipt=member%40example.org",),
                )
            )["prefilled_email_param"],
            1,
        )

    def test_receipts_and_reply_prefixes_supply_context_without_a_verdict(self):
        receipt = Mail("The order total is shown below. Manage email preferences.", 0, "test", "Receipt")
        features = extract_benign_suppressor_features(receipt)
        self.assertEqual(features["transactional_receipt_markers"], 1)
        self.assertEqual(features["newsletter_bulk_markers"], 1)
        unverified = Mail("Here are the minutes.", 0, "test", "Re: Meeting")
        quoted = Mail("Here are the minutes.\n\n> What did we decide?", 0, "test", "Re: Meeting")
        self.assertEqual(extract_benign_suppressor_features(unverified)["conversational_reply_markers"], 0)
        self.assertEqual(extract_benign_suppressor_features(quoted)["conversational_reply_markers"], 1)

    def test_sparse_flags_respect_credential_context(self):
        no_request = Mail("Your account code is [CODE]. Never share your verification code.", 0, "test")
        delivery_request = Mail("For delivery, please send us your verification code.", 1, "test")
        first = extract_sparse_header_short_features(no_request)
        second = extract_sparse_header_short_features(delivery_request)
        self.assertEqual(first["sender_missing"], 1)
        self.assertEqual(first["reply_to_missing"], 1)
        self.assertEqual(first["short_sms_delivery_account_lure"], 0)
        self.assertEqual(second["short_sms_delivery_account_lure"], 1)
        callback = Mail("For a billing refund, call 202-555-0142 today.", 1, "test")
        self.assertEqual(extract_sparse_header_short_features(callback)["short_callback_refund_scam"], 1)

    def test_text_views_cover_body_and_mask_link_email_and_numeric_values(self):
        row = Mail(
            "Opening "
            + "word " * 120
            + "Center "
            + "word " * 120
            + "Closing 123456 https://private.example/value",
            0,
            "test",
            "For name@example.org",
            links=({"url": "https://private.example/value", "label": "Read newsletter"},),
        )
        leading, trailing, middle = two_view_texts(row, include_middle=True)
        self.assertIn("Opening", leading)
        self.assertIn("Closing", trailing)
        self.assertIn("Read newsletter", trailing)
        self.assertIn("Center", middle)
        self.assertNotIn("Center", leading + trailing)
        views = leading + trailing + middle
        for value in ("name@example.org", "private.example", "123456"):
            self.assertNotIn(value, views)

    def test_prototypes_never_fit_to_held_out_embeddings(self):
        fit_ids = [0, 1, 2, 3]
        fit_labels = [0, 0, 1, 1]
        vectors = np.array([[1, 0], [1, 0.2], [-1, 0], [-1, 0.2], [0, 1]], dtype=float)
        margins, centers = compute_prototype_margin(vectors, fit_ids, fit_labels, n_clusters=1)
        vectors[-1] = [100, 1]
        changed_margins, changed_centers = compute_prototype_margin(
            vectors, fit_ids, fit_labels, n_clusters=1
        )
        for label in (0, 1):
            np.testing.assert_allclose(centers[label], changed_centers[label])
        np.testing.assert_allclose(margins[fit_ids], changed_margins[fit_ids])
        self.assertLess(margins[0], 0)
        self.assertGreater(margins[2], 0)
        with self.assertRaises(ValueError):
            compute_prototype_margin(vectors, fit_ids, fit_labels + [1])
