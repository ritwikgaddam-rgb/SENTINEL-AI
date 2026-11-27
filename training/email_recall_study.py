"""Offline source-held-out email evaluation. Artifacts and reports stay under .runtime."""
import argparse
from collections import Counter, defaultdict
from contextlib import closing
import csv
from dataclasses import dataclass
from email import message_from_bytes, message_from_binary_file, policy
from email.utils import parseaddr
from hashlib import file_digest
import ipaddress
import json
import mailbox
import math
import os
from pathlib import Path
import re
import tarfile
from time import perf_counter
from urllib.parse import parse_qsl, urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_curve
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import FeatureUnion, make_pipeline
from sklearn.preprocessing import MaxAbsScaler
from sklearn.svm import LinearSVC

from backend import server
from backend.assessments import (
    BRANDS, LOOKALIKES, PUBLIC_SUFFIX, email_evidence, link_items, registrable, split_url
)
from training.compare_email_models import mixed_features, model_text, normalized, prepare, template_groups, word_features
from training.train_reviewed_features import evaluate

ROOT = Path(__file__).resolve().parents[1]
LABELS = {"Safe Email": 0, "Phishing Email": 1}
FALSE_POSITIVE_BUDGET = .05
OOF_TARGET_FPR = .025

KNOWN_ESP_DOMAINS = frozenset({
    "sendgrid.net", "ct.sendgrid.net",
    "mailchimp.com", "mcsv.net", "list-manage.com",
    "awstrack.me", "amazonses.com",
    "hubspotemail.net", "hubspot.com", "hs-sites.com", "hubspotlinks.com",
    "marketo.com", "mktomail.com",
    "constantcontact.com", "rs6.net",
    "sailthru.com", "emarsys.net", "campaign-archive.com",
})

FREE_WEBMAIL_DOMAINS = frozenset({
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "mail.com", "zoho.com", "yandex.com", "protonmail.com", "proton.me",
    "gmx.com", "fastmail.com", "ymail.com", "live.com",
})

TUNNEL_OR_FREE_HOSTS = frozenset({
    "ngrok.io", "ngrok-free.app", "localtunnel.me", "trycloudflare.com",
    "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
    "glitch.me", "herokuapp.com", "vercel.app", "netlify.app",
    "surge.sh", "github.io",
})

OPEN_REDIRECT_PARAMS = frozenset({
    "url", "redirect", "redirect_uri", "redirect_url", "next", "dest", "destination",
    "target", "return", "return_url", "returnto", "r", "link", "goto", "uri",
})

HIGH_VALUE_DOMAINS = frozenset({
    "paypal.com", "microsoft.com", "apple.com", "google.com", "amazon.com",
    "netflix.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "docusign.net", "dropbox.com", "adobe.com", "meta.com", "facebook.com",
    "instagram.com", "linkedin.com", "twitter.com", "x.com"
})

HIGH_RISK_TLDS = frozenset({
    ".xyz", ".top", ".click", ".icu", ".online", ".site", ".cfd", ".work",
    ".buzz", ".monster", ".fit", ".rest", ".club", ".bar", ".wiki", ".vip",
    ".gq", ".ml", ".cf", ".tk", ".ga"
})

ACTION_ANCHOR_PATTERNS = re.compile(
    r"\b(?:verify|sign in|log in|view document|review invoice|update payment|"
    r"unlock account|confirm identity|access document|download invoice|"
    r"pay now|click here|open link|authenticate|reset password)\b", re.I
)

CALLBACK_PHISHING_PATTERN = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
)

CALLBACK_KEYWORDS = re.compile(
    r"\b(?:call|toll[- ]free|helpline|support line|cancel(?:lation)?|refund|charged|"
    r"invoice|subscription|geek squad|mcafee|norton|paypal support|helpdesk)\b", re.I
)

WIRE_URGENCY_PATTERN = re.compile(
    r"\b(?:wire transfer|direct deposit|payroll|gift card|gift cards|bank details|"
    r"remittance|swift code|ach transfer|routing number|same[- ]day transfer)\b", re.I
)

ATTACHMENT_LURE_PATTERN = re.compile(
    r"\b(?:attached (?:invoice|document|file|receipt|remittance|statement|pdf)|"
    r"see attached|review attached|find attached|attachment)\b", re.I
)


def levenshtein_similarity(s1, s2):
    m, n = len(s1), len(s2)
    if m == 0 or n == 0:
        return 0.0
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if s1[i-1] == s2[j-1] else 1
            dp[i][j] = min(dp[i-1][j] + 1, dp[i][j-1] + 1, dp[i-1][j-1] + cost)
    dist = dp[m][n]
    return 1.0 - (dist / max(m, n))


def domain_entropy(domain):
    if not domain:
        return 0.0
    counts = Counter(domain)
    n = len(domain)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def domain_lexical_risk(domain):
    """
    Computes typosquat similarity to high-value targets, Shannon entropy,
    digit-to-letter ratio, hyphen count, and high-risk TLD indicator.
    """
    if not domain:
        return {
            "is_typosquat": 0,
            "max_target_sim": 0.0,
            "domain_entropy": 0.0,
            "digit_letter_ratio": 0.0,
            "hyphen_count": 0,
            "high_risk_tld": 0,
        }

    domain_lower = domain.lower().strip()
    digits = sum(c.isdigit() for c in domain_lower)
    letters = sum(c.isalpha() for c in domain_lower)
    digit_letter_ratio = digits / max(letters, 1)
    hyphen_count = domain_lower.count("-")
    has_high_risk_tld = int(any(domain_lower.endswith(tld) for tld in HIGH_RISK_TLDS))
    ent = domain_entropy(domain_lower)

    max_sim = 0.0
    is_typosquat = 0
    for target in HIGH_VALUE_DOMAINS:
        sim = levenshtein_similarity(domain_lower, target)
        if sim > max_sim:
            max_sim = sim
        if 0.82 <= sim < 1.0:
            is_typosquat = 1

    return {
        "is_typosquat": is_typosquat,
        "max_target_sim": round(max_sim, 3),
        "domain_entropy": round(ent, 3),
        "digit_letter_ratio": round(digit_letter_ratio, 3),
        "hyphen_count": hyphen_count,
        "high_risk_tld": has_high_risk_tld,
    }


def extract_domain_agnostic_features(sender="", links=(), subject="", reply_to="", body=""):
    """
    Extract domain-agnostic interaction and lexical features independent of static brand lists.
    """
    name, address = parseaddr(sender or "")
    sender_domain = address.rpartition("@")[2].lower().strip()
    sender_reg = registrable(sender_domain) if sender_domain else ""
    is_freemail = int(sender_reg in FREE_WEBMAIL_DOMAINS or sender_domain in FREE_WEBMAIL_DOMAINS)

    sender_lex = domain_lexical_risk(sender_reg)
    typosquat_detected = sender_lex["is_typosquat"]
    any_high_risk_tld = sender_lex["high_risk_tld"]
    max_domain_entropy = sender_lex["domain_entropy"]
    max_digit_letter_ratio = sender_lex["digit_letter_ratio"]
    max_hyphen_count = sender_lex["hyphen_count"]

    has_external_non_esp_link = 0
    sender_vs_href_mismatch = 0
    has_action_anchor = 0

    for item in links:
        url = item["url"] if isinstance(item, dict) else str(item)
        label = item.get("label", "") if isinstance(item, dict) else ""
        if not url:
            continue
        try:
            _, host, _ = split_url(url, assume_https=True)
        except (ValueError, UnicodeError):
            continue

        host_reg = registrable(host)
        is_esp = is_esp_domain(host)

        if label and ACTION_ANCHOR_PATTERNS.search(label):
            has_action_anchor = 1

        if not is_esp:
            has_external_non_esp_link = 1
            if sender_reg and host_reg and sender_reg != host_reg:
                sender_vs_href_mismatch = 1

            link_lex = domain_lexical_risk(host_reg)
            if link_lex["is_typosquat"]:
                typosquat_detected = 1
            if link_lex["high_risk_tld"]:
                any_high_risk_tld = 1
            max_domain_entropy = max(max_domain_entropy, link_lex["domain_entropy"])
            max_digit_letter_ratio = max(max_digit_letter_ratio, link_lex["digit_letter_ratio"])
            max_hyphen_count = max(max_hyphen_count, link_lex["hyphen_count"])

    free_webmail_with_external_cta = int(is_freemail and (has_external_non_esp_link or has_action_anchor))

    words = len(re.findall(r"\b\w+\b", body))
    link_density = len(links) / max(words, 10)

    return {
        "sender_vs_href_mismatch": sender_vs_href_mismatch,
        "free_webmail_with_external_cta": free_webmail_with_external_cta,
        "has_action_anchor": has_action_anchor,
        "has_external_non_esp_link": has_external_non_esp_link,
        "typosquat_detected": typosquat_detected,
        "any_high_risk_tld": any_high_risk_tld,
        "max_domain_entropy": round(max_domain_entropy, 3),
        "max_digit_letter_ratio": round(max_digit_letter_ratio, 3),
        "max_hyphen_count": max_hyphen_count,
        "link_density": round(link_density, 3),
    }


def extract_linkless_social_engineering_features(body="", subject="", links=()):
    """
    Extract callback phishing, wire urgency, and attachment lures for linkless regime.
    """
    text = f"{subject}\n{body}"
    has_phone = bool(CALLBACK_PHISHING_PATTERN.search(text))
    has_callback_words = bool(CALLBACK_KEYWORDS.search(text))
    callback_phishing_signal = int(has_phone and has_callback_words)

    wire_urgency_signal = int(bool(WIRE_URGENCY_PATTERN.search(text)))
    attachment_lure_signal = int(bool(ATTACHMENT_LURE_PATTERN.search(text)))
    regime_no_links = int(len(links) == 0)

    return {
        "callback_phishing_signal": callback_phishing_signal,
        "wire_urgency_signal": wire_urgency_signal,
        "attachment_lure_signal": attachment_lure_signal,
        "regime_no_links": regime_no_links,
    }


def make_dense_semantic_pipeline(n_components=100):
    """
    Compact subword/character + word TF-IDF Latent Semantic Analysis pipeline.
    Projects corpus-specific TF-IDF features into a lower-dimensional lexical space.
    """
    text_union = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, max_features=15000)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True, max_features=25000)),
    ])
    return make_pipeline(
        text_union,
        TruncatedSVD(n_components=n_components, random_state=42),
        LogisticRegression(C=1.0, max_iter=500, random_state=42),
    )


def is_esp_domain(host):
    reg = registrable(host)
    if reg in KNOWN_ESP_DOMAINS:
        return True
    return any(host == esp or host.endswith("." + esp) for esp in KNOWN_ESP_DOMAINS)


def extract_structural_link_features(links):
    """
    Extract privacy-safe structural indicators from message links.
    Returns boolean flags and counts without logging raw URLs.
    """
    if not links:
        return {
            "total_links": 0,
            "has_links": 0,
            "anchor_url_mismatch": 0,
            "has_raw_ip": 0,
            "has_punycode": 0,
            "has_deep_subdomain": 0,
            "has_open_redirect": 0,
            "has_tunnel_host": 0,
            "is_esp_safelisted": 0,
            "url_obfuscation_any": 0,
        }

    total_links = len(links)
    anchor_mismatch = 0
    has_raw_ip = 0
    has_punycode = 0
    has_deep_subdomain = 0
    has_open_redirect = 0
    has_tunnel_host = 0
    is_esp_safelisted = 0

    for item in links:
        url = item["url"] if isinstance(item, dict) else str(item)
        label = item.get("label", "") if isinstance(item, dict) else ""
        if not url:
            continue
        try:
            parts, host, ip = split_url(url, assume_https=True)
        except (ValueError, UnicodeError):
            continue

        host_reg = registrable(host)
        is_esp = is_esp_domain(host)
        if is_esp:
            is_esp_safelisted = 1

        if ip is not None:
            has_raw_ip = 1

        if any(part.startswith("xn--") for part in host.split(".")) or host.startswith("xn--"):
            has_punycode = 1

        ext = PUBLIC_SUFFIX(host)
        if ip is None and ext.subdomain:
            subdomain_labels = ext.subdomain.split(".")
            if len(subdomain_labels) >= 3:
                has_deep_subdomain = 1

        if host_reg in TUNNEL_OR_FREE_HOSTS or any(host.endswith("." + th) for th in TUNNEL_OR_FREE_HOSTS):
            has_tunnel_host = 1

        if parts.query:
            try:
                qsl = parse_qsl(parts.query, max_num_fields=50, errors="replace")
                for qk, qv in qsl:
                    if qk.lower() in OPEN_REDIRECT_PARAMS:
                        if "://" in qv or qv.startswith("//") or "." in qv:
                            has_open_redirect = 1
                            break
            except Exception:
                pass

        if label:
            url_match = re.search(r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*)", label)
            if url_match:
                disp_str = url_match.group(1).rstrip(".,;!?)")
                try:
                    disp_reg = registrable(disp_str)
                    if disp_reg and disp_reg != host_reg:
                        anchor_mismatch = 1
                except Exception:
                    pass
            for brand, brand_domain in BRANDS.items():
                if re.search(rf"\b{re.escape(brand)}\b", label, re.I):
                    if host_reg != brand_domain and host_reg not in KNOWN_ESP_DOMAINS:
                        anchor_mismatch = 1
                        break

    url_obfuscation = int(has_raw_ip or has_punycode or has_deep_subdomain or has_open_redirect or has_tunnel_host)

    return {
        "total_links": total_links,
        "has_links": int(total_links > 0),
        "anchor_url_mismatch": anchor_mismatch,
        "has_raw_ip": has_raw_ip,
        "has_punycode": has_punycode,
        "has_deep_subdomain": has_deep_subdomain,
        "has_open_redirect": has_open_redirect,
        "has_tunnel_host": has_tunnel_host,
        "is_esp_safelisted": is_esp_safelisted,
        "url_obfuscation_any": url_obfuscation,
    }


def extract_sender_display_features(sender="", reply_to=""):
    """
    Extract display name vs sender address domain mismatch and freemail flags.
    """
    name, address = parseaddr(sender or "")
    sender_domain = address.rpartition("@")[2].lower().strip()
    sender_reg = registrable(sender_domain) if sender_domain else ""

    is_freemail = int(sender_reg in FREE_WEBMAIL_DOMAINS or sender_domain in FREE_WEBMAIL_DOMAINS)
    is_esp = int(sender_reg in KNOWN_ESP_DOMAINS)

    display_brand_mismatch = 0
    if name and sender_reg:
        for brand, brand_domain in BRANDS.items():
            if re.search(rf"\b{re.escape(brand)}\b", name, re.I):
                if sender_reg != brand_domain:
                    display_brand_mismatch = 1
                    break
        if is_freemail and not display_brand_mismatch:
            if re.search(r"\b(?:support|security|helpdesk|billing|service|account|verification|administrator|apple|paypal|google|microsoft|amazon|netflix|bank)\b", name, re.I):
                display_brand_mismatch = 1

    reply_to_mismatch = 0
    if reply_to:
        reply_addr = parseaddr(reply_to)[1]
        reply_domain = reply_addr.rpartition("@")[2].lower().strip()
        reply_reg = registrable(reply_domain) if reply_domain else ""
        if reply_reg and sender_reg and reply_reg != sender_reg:
            reply_to_mismatch = 1

    return {
        "display_brand_mismatch": display_brand_mismatch,
        "sender_is_freemail": is_freemail,
        "sender_is_esp": is_esp,
        "reply_to_mismatch": reply_to_mismatch,
    }


def extract_privacy_safe_features(row_or_body, sender="", links=(), subject="", reply_to=""):
    """
    Combine link, sender, domain-agnostic, and linkless structural features for a message or row.
    """
    if isinstance(row_or_body, Mail):
        body = row_or_body.body
        sender = row_or_body.sender
        links = row_or_body.links
        subject = row_or_body.subject
        reply_to = row_or_body.reply_to
    else:
        body = str(row_or_body)

    feat = extract_structural_link_features(links)
    feat.update(extract_sender_display_features(sender, reply_to))
    feat.update(extract_domain_agnostic_features(sender, links, subject, reply_to, body))
    feat.update(extract_linkless_social_engineering_features(body, subject, links))
    feat.update(
        subject_present=int(bool(subject)),
        sender_present=int(bool(sender)),
        reply_to_present=int(bool(reply_to)),
    )
    return feat


def audit_current_errors(labels, predictions, rows, probabilities=None):
    """
    Audit detection errors sliced by link count, sender category, and score margins.
    """
    labels = np.asarray(labels)
    predictions = np.asarray(predictions)
    probs = np.asarray(probabilities) if probabilities is not None else None

    fps = np.where((labels == 0) & (predictions == 1))[0]
    fns = np.where((labels == 1) & (predictions == 0))[0]

    def slice_cohort(indices):
        by_links = {"0_links": 0, "ge_1_links": 0}
        by_sender = {"freemail": 0, "esp_transactional": 0, "other_domain": 0}
        by_score_margin = {"margin_low": 0, "margin_mid": 0, "margin_high": 0}

        for idx in indices:
            row = rows[idx]
            feat = extract_privacy_safe_features(row)
            if feat["total_links"] == 0:
                by_links["0_links"] += 1
            else:
                by_links["ge_1_links"] += 1

            if feat["sender_is_freemail"]:
                by_sender["freemail"] += 1
            elif feat["sender_is_esp"]:
                by_sender["esp_transactional"] += 1
            else:
                by_sender["other_domain"] += 1

            if probs is not None:
                p = float(probs[idx])
                if p < 0.35:
                    by_score_margin["margin_low"] += 1
                elif p <= 0.70:
                    by_score_margin["margin_mid"] += 1
                else:
                    by_score_margin["margin_high"] += 1

        return {
            "count": len(indices),
            "by_links": by_links,
            "by_sender": by_sender,
            "by_score_margin": by_score_margin,
        }

    return {
        "false_positives": slice_cohort(fps),
        "false_negatives": slice_cohort(fns),
        "total_evaluated": len(labels),
    }


def choose_oof_threshold(labels, oof_probabilities, ham_probabilities=(), target_fpr=OOF_TARGET_FPR):
    """
    Select threshold strictly on out-of-fold validation targeting <= target_fpr (2.5%)
    and zero alerts on the benign short ham cohort.
    """
    labels = np.asarray(labels)
    oof_p = np.asarray(oof_probabilities)
    ham_p = np.asarray(ham_probabilities) if len(ham_probabilities) > 0 else np.array([])

    # Alerts use strict >. The largest benign guard score is itself a valid
    # cutoff, even when no validation example has that exact score.
    thresholds = np.unique(np.r_[0., oof_p, ham_p, 1.])

    def at(t):
        alerts = oof_p > t
        fpr = np.mean(alerts[labels == 0]) if np.sum(labels == 0) > 0 else 0.0
        recall = np.mean(alerts[labels == 1]) if np.sum(labels == 1) > 0 else 0.0
        short_fpr = np.mean(ham_p > t) if len(ham_p) > 0 else 0.0
        return fpr, recall, short_fpr

    viable = [
        (recall, -fpr, -short_fpr, float(t))
        for t in thresholds
        for fpr, recall, short_fpr in (at(t),)
        if fpr <= target_fpr and short_fpr == 0.0
    ]
    if not viable:
        return 1.0
    return max(viable)[-1]


class CalibratedStackingClassifier:
    """
    Calibrated stacking meta-learner combining calibrated lexical TF-IDF probability,
    lexical SVD probability, domain-agnostic structural signals, and linkless regime features.
    """
    def __init__(self, base_text_pipeline=None, dense_text_pipeline=None, meta_penalty=4.0):
        self.base_text_pipeline = base_text_pipeline or make_pipeline(
            word_features(), LinearSVC(C=0.5, class_weight="balanced", random_state=42)
        )
        self.dense_text_pipeline = dense_text_pipeline or make_dense_semantic_pipeline(n_components=100)
        self.calibrated_lexical_model = None
        self.calibrated_dense_model = None
        self.meta_penalty = meta_penalty
        self.meta_learner = LogisticRegression(
            C=0.5,
            class_weight={0: meta_penalty, 1: 1.0},
            max_iter=500,
            random_state=42,
        )
        self.threshold = 0.5
        self.feature_names = [
            "lexical_prob", "dense_prob", "has_links", "regime_no_links",
            "anchor_url_mismatch", "sender_vs_href_mismatch", "free_webmail_with_external_cta",
            "has_action_anchor", "typosquat_detected", "any_high_risk_tld",
            "url_obfuscation_any", "is_esp_safelisted", "display_brand_mismatch",
            "sender_is_freemail", "reply_to_mismatch", "callback_phishing_signal",
            "wire_urgency_signal", "attachment_lure_signal",
            "regime_no_links_x_dense", "regime_no_links_x_callback",
            "links_present_x_mismatch", "links_present_x_freemail_cta"
        ]

    def _extract_meta_features(self, lexical_probs, dense_probs, rows):
        feats = [extract_privacy_safe_features(r) for r in rows]
        regime_no_links = np.array([f["regime_no_links"] for f in feats])
        links_present = 1.0 - regime_no_links
        sender_mismatch = np.array([f["sender_vs_href_mismatch"] for f in feats])
        freemail_cta = np.array([f["free_webmail_with_external_cta"] for f in feats])
        callback = np.array([f["callback_phishing_signal"] for f in feats])

        cols = [
            lexical_probs,
            dense_probs,
            np.array([f["has_links"] for f in feats]),
            regime_no_links,
            np.array([f["anchor_url_mismatch"] for f in feats]),
            sender_mismatch,
            freemail_cta,
            np.array([f["has_action_anchor"] for f in feats]),
            np.array([f["typosquat_detected"] for f in feats]),
            np.array([f["any_high_risk_tld"] for f in feats]),
            np.array([f["url_obfuscation_any"] for f in feats]),
            np.array([f["is_esp_safelisted"] for f in feats]),
            np.array([f["display_brand_mismatch"] for f in feats]),
            np.array([f["sender_is_freemail"] for f in feats]),
            np.array([f["reply_to_mismatch"] for f in feats]),
            callback,
            np.array([f["wire_urgency_signal"] for f in feats]),
            np.array([f["attachment_lure_signal"] for f in feats]),
            # Regime interaction terms
            regime_no_links * dense_probs,
            regime_no_links * callback,
            links_present * sender_mismatch,
            links_present * freemail_cta,
        ]
        return np.column_stack(cols)

    def fit_and_tune_oof(self, fit_rows, y_fit, cal_rows, y_cal, ham_rows=(), n_splits=5, target_fpr_sweep=(0.02, 0.025, 0.03, 0.035)):
        """Fit meta features on held-out groups, calibrate and tune on separate validation groups."""
        y_fit, y_cal = np.asarray(y_fit), np.asarray(y_cal)
        if set(y_fit) != {0, 1} or set(y_cal) != {0, 1}:
            raise ValueError("Both fit and validation need legitimate and phishing examples.")
        groups = np.array(template_groups([(normalized_key(r),) for r in [*fit_rows, *cal_rows]]))
        fit_groups, val_groups = np.split(groups, [len(fit_rows)])
        if set(fit_groups) & set(val_groups):
            raise ValueError("A template group occurs in both fit and validation.")
        train_text = np.array([model_text(r.body, r.subject) for r in fit_rows])
        val_text = np.array([model_text(r.body, r.subject) for r in cal_rows])
        calibration, tune = next(StratifiedGroupKFold(2, shuffle=True, random_state=27)
                                 .split(val_text, y_cal, val_groups))
        if min(Counter(y_cal[calibration]).values()) < 2 or len(set(y_cal[calibration])) != 2 or len(set(y_cal[tune])) != 2:
            raise ValueError("Validation requires multiple independent groups of each label.")

        def calibrated(pipeline, indexes):
            trained = clone(pipeline).fit(train_text[indexes], y_fit[indexes])
            return CalibratedClassifierCV(FrozenEstimator(trained), method="sigmoid", cv=2).fit(
                val_text[calibration], y_cal[calibration])

        oof = np.empty((len(fit_rows), 2))
        folds = StratifiedGroupKFold(n_splits, shuffle=True, random_state=42)
        for train, held in folds.split(train_text, y_fit, fit_groups):
            for column, pipeline in enumerate((self.base_text_pipeline, self.dense_text_pipeline)):
                oof[held, column] = calibrated(pipeline, train).predict_proba(train_text[held])[:, 1]
        self.meta_learner.fit(self._extract_meta_features(oof[:, 0], oof[:, 1], fit_rows), y_fit)
        indexes = np.arange(len(y_fit))
        self.calibrated_lexical_model = calibrated(self.base_text_pipeline, indexes)
        self.calibrated_dense_model = calibrated(self.dense_text_pipeline, indexes)
        scores = self.predict_proba([cal_rows[i] for i in tune])
        guards = self.predict_proba(ham_rows) if len(ham_rows) else []
        self.sweep_results = {}
        for budget in target_fpr_sweep:
            cut = choose_oof_threshold(y_cal[tune], scores, guards, target_fpr=budget)
            selected = scores > cut
            self.sweep_results[str(budget)] = {"threshold": cut,
                "validation_fpr": float(selected[y_cal[tune] == 0].mean()),
                "validation_recall": float(selected[y_cal[tune] == 1].mean())}
        self.threshold = choose_oof_threshold(y_cal[tune], scores, guards, target_fpr=OOF_TARGET_FPR)
        return self.threshold

    def predict_proba(self, rows):
        text_inputs = [model_text(r.body, r.subject) for r in rows]
        if self.calibrated_lexical_model is None:
            raise ValueError("Fit the stacking model before requesting predictions.")
        else:
            p_lex = self.calibrated_lexical_model.predict_proba(text_inputs)[:, 1]
            p_dense = self.calibrated_dense_model.predict_proba(text_inputs)[:, 1]
        meta_X = self._extract_meta_features(p_lex, p_dense, rows)
        return self.meta_learner.predict_proba(meta_X)[:, 1]

    def predict(self, rows):
        return (self.predict_proba(rows) > self.threshold).astype(int)



@dataclass(frozen=True)
class Mail:
    body: str
    label: int
    source: str
    subject: str = ""
    sender: str = ""
    reply_to: str = ""
    links: tuple = ()


def corpus_mail(message, label, source):
    part = message.get_body(preferencelist=("plain", "html"))
    if part is None:
        return None
    try:
        body = part.get_content()[:20000]
        links = ()
        if part.get_content_subtype() == "html":
            body, anchors, _ = link_items("", body, ())
            links = tuple({"url": item["url"], "label": item["display_text"]} for item in anchors)
        return Mail(body, label, source, str(message.get("Subject") or "")[:500],
                    str(message.get("From") or "")[:500], str(message.get("Reply-To") or "")[:500], links)
    except (AttributeError, LookupError, UnicodeError, ValueError):
        return None


def corpus(path, label, counts):
    output = []

    def read(message):
        counts["parsed"] += 1
        row = corpus_mail(message, label, path.name)
        if row is not None and len(normalized(row.body)) >= 4:
            output.append(row)
        else:
            counts["missing_or_unusable"] += 1

    if path.suffix == ".bz2":
        with tarfile.open(path, "r:bz2") as archive:
            for entry in archive:
                if entry.isfile() and Path(entry.name).name != "cmds":
                    if not 0 < entry.size < 1_000_000:
                        counts["size_excluded"] += 1
                        continue
                    with archive.extractfile(entry) as message:
                        read(message_from_bytes(message.read(), policy=policy.default))
    else:
        with closing(mailbox.mbox(path, create=False)) as messages:
            for key in messages.iterkeys():
                with messages.get_file(key) as message:
                    read(message_from_binary_file(message, policy=policy.default))
    return output


def csv_mail(path):
    csv.field_size_limit(50_000_000)
    with path.open(newline="") as source:
        return list(csv.DictReader(source))


def normalized_key(row):
    # Suppress formatting, URL values, e-mail domains and digit changes in group keys.
    return " ".join(normalized(row.body))


def make_partitions(partitions):
    """Remove exact label conflicts and keep related templates in one partition."""
    order = ("manual", "real", "validation", "fit")
    rows = [(name, row, normalized_key(row)) for name in order for row in partitions[name]]
    groups = template_groups([(key,) for _, _, key in rows])
    labels = defaultdict(set)
    for _, row, key in rows:
        labels[key].add(row.label)
    report = {name: Counter(input=len(partitions[name])) for name in order}
    result = {name: [] for name in order}
    seen, group_owner = set(), {}
    for (name, row, key), group in zip(rows, groups):
        if not key:
            report[name]["missing"] += 1
        elif len(labels[key]) > 1:
            report[name]["conflicting"] += 1
        elif key in seen:
            report[name]["exact_duplicate"] += 1
        elif group_owner.setdefault(group, name) != name:
            report[name]["cross_partition_template"] += 1
        else:
            seen.add(key)
            result[name].append((row, group))
    for name in order:
        report[name]["retained"] = len(result[name])
        report[name].update({f"label_{k}": v for k, v in Counter(row.label for row, _ in result[name]).items()})
        report[name]["groups"] = len({group for _, group in result[name]})
    return result, report


# Benign examples authored for this study. The acceptance strings in tests
# remain separate. Augmentation supplies modern/short benign text to old mail.
FIT_HAM = (
    "Hi there!", "Morning!", "Got a minute?", "Thanks for your help.", "See you on Saturday.",
    "Can you bring the notebook?", "We have a lab session after lunch.", "The essay draft is attached.",
    "Practice is at four on the east field.", "The library books are due Friday.",
    "No class on Monday. The lesson moves to Wednesday.", "I've put the team notes in the shared folder.",
    "That time works for me.", "Sorry I missed the meeting.", "Let's review the homework together.",
    "Please bring your signed permission slip to the office.", "Can we move our call to the afternoon?",
    "I finished the draft and left comments in the margin.", "Please send the slides when you get a chance.",
    "Security reminder: use the official app to review recent sign-ins.",
    "Keep your recovery codes somewhere private. Our staff will never ask for them.",
    "If you suspect an email is fake, report it to the support team.",
    "A password manager can help you use a unique password for everything.",
    "The security workshop covers how to spot a fake login screen.",
    "The invoice is ready for the regular accounting review.",
    "Your class project has been approved. Plan to present next week.",
    "The test results are ready in the school portal you normally use.",
    "I will pick up the tickets at the door.",
    "How did the rehearsal go?", "Looks good to me.", "Can you confirm our appointment for Tuesday?",
)
DEV_HAM = (
    "Hey, good evening.", "Are you free for a quick chat?", "Talk later.", "That was really helpful.",
    "I'll meet you outside the gym.", "The teacher has moved the quiz to Thursday.",
    "Please return the science worksheet tomorrow.", "My homework was done but I forget to attach it.",
    "Can you check whether I uploaded the right assignment?",
    "Never give a caller the recovery code for your account.",
    "Someone asked me about a password reset. I told them to contact support.",
    "Turn on two-step verification using the settings menu.",
    "Please confirm you received the meeting notes.",
    "The department calendar has the updated room number and time.",
    "The order arrived today. Could you check the receipt?", "Please let me know if you have questions.",
    "I have sent the report to our usual reviewer.", "Their documentation is at https://example.org/help.",
)


def dataset(args):
    audits = {}
    sources = sorted(args.source_dir.glob("phishing-*"))
    ham_paths = sorted(args.ham_dir.glob("*.tar.bz2"))
    fit, validation = [], []
    for paths, label, validation_suffix in ((ham_paths, 0, "easy_ham_2.tar.bz2"), (sources, 1, "2024")):
        for path in paths:
            audit = audits[path.name] = Counter()
            extracted = corpus(path, label, audit)
            audit["retained_before_dedup"] = len(extracted)
            (validation if path.name.endswith(validation_suffix) else fit).extend(extracted)
    fit.extend(Mail(body, 0, "authored_fit") for body in FIT_HAM)
    dev_ham = [Mail(body, 0, "authored_validation") for body in DEV_HAM]
    raw = json.loads((args.source_dir / "seed.json").read_text())
    entries = prepare(raw)
    # Recover author-provided visible URLs without inventing anchor labels.
    refs = {}
    for item in raw:
        if item.get("Source") == "Manual" and item.get("Language") == "en":
            key = " ".join(normalized(str(item.get("Body") or "")[:20000]))
            urls = item.get("URL")
            refs.setdefault(key, tuple(url for url in urls if isinstance(url, str)) if isinstance(urls, list) else ())
    manual = [Mail(body, label, "PhishFuzzer manual", subject, sender, links=refs.get(key, ()))
              for body, subject, sender, label, key in entries]
    zen = csv_mail(args.source_dir / "validation-v3.csv")
    meta = csv_mail(args.source_dir / "validation-v3-meta.csv")
    if len(zen) != len(meta) or any(row["Email Type"] != m["email_type"] for row, m in zip(zen, meta)):
        raise ValueError("Short-message benchmark and source metadata do not align.")
    real = [Mail(row["Email Text"], LABELS[row["Email Type"]], "Zenodo real")
            for row, m in zip(zen, meta) if m["source_category"] == "original_v1"]
    if len(real) != 100:
        raise ValueError(f"Expected 100 real Zenodo records. Found {len(real)}.")
    audits["PhishFuzzer"] = {"total": len(raw), "selected_manual_english_after_screen": len(manual)}
    if args.public_seeds:
        public = [
            row for row in raw
            if row.get("Source") != "Manual" and row.get("Language") == "en"
            and row.get("Type") in {"Valid", "Phishing"} and str(row.get("Body") or "").strip()
        ]
        audits["PhishFuzzer"]["public_fit_before_screen"] = len(public)
        fit.extend(Mail(str(row["Body"])[:20000], int(row["Type"] == "Phishing"), "PhishFuzzer public",
                        str(row.get("Subject") or "")[:500], str(row.get("Sender") or "")[:500]) for row in public)
    audits["Zenodo"] = {"total": len(zen), "real": len(real), "excluded_template_generated": len(zen) - len(real)}
    if args.legacy_csv is not None:
        rows = csv_mail(args.legacy_csv)
        valid = [row for row in rows if row["Email Type"] in LABELS and (row["Email Text"] or "").strip()]
        audits["local_legacy_csv"] = {"rows": len(rows), "labels": dict(Counter(x["Email Type"] for x in rows)),
                                      "missing_or_invalid": len(rows) - len(valid)}
        fit.extend(Mail(row["Email Text"][:20000], LABELS[row["Email Type"]], "local legacy CSV") for row in valid)
    return make_partitions({"fit": fit, "validation": validation, "manual": manual, "real": real}), dev_ham, audits


def frame(rows, context=False, structural=False):
    data = pd.DataFrame({"text": [model_text(row.body, row.subject) for row in rows]})
    if context or structural:
        features = []
        for row in rows:
            details = email_evidence(row.body, row.sender, row.links, row.subject, row.reply_to)
            numeric = server.email_features(details)
            # No corpus/source identifier, raw header strings or grammar in the learned signal.
            numeric.update(subject_present=int(bool(row.subject)), sender_present=int(bool(row.sender)),
                           reply_to_present=int(bool(row.reply_to)),
                           weak_links=sum(any(m["severity"] == "medium" for m in link["markers"])
                                          for link in details["links"]))
            if structural:
                numeric.update(extract_privacy_safe_features(row))
            features.append(numeric)
        data = pd.concat([data, pd.DataFrame(features)], axis=1)
    return data


def choose_threshold(labels, probability, ham_probability):
    return choose_oof_threshold(labels, probability, ham_probability, target_fpr=FALSE_POSITIVE_BUDGET)


def score_set(labels, probabilities, threshold, *, raw=False):
    result = evaluate(labels, probabilities > threshold, probabilities if raw else None)
    result.update(threshold=threshold, coverage=1., abstention_rate=0.)
    if raw:
        p, r, t = precision_recall_curve(labels, probabilities)
        result.update(average_precision=float(average_precision_score(labels, probabilities)),
                      curve={"precision": p.tolist(), "recall": r.tolist(), "threshold": t.tolist()})
    return result


def main(args):
    os.environ.pop("SENTINELAI_LANGUAGETOOL_PORT", None)
    os.umask(0o077)  # A candidate vocabulary can contain terms from the source corpus.
    (partitions, counts), authored_ham, audits = dataset(args)
    args.output.mkdir(parents=True, exist_ok=False)
    print("Partitions", counts, flush=True)
    fit = [row for row, _ in partitions["fit"]]
    validation, groups = zip(*partitions["validation"])
    yv = np.array([row.label for row in validation])
    calibration, tune = next(StratifiedGroupKFold(n_splits=2, shuffle=True, random_state=27)
                             .split(validation, yv, groups))
    assert set(np.array(groups)[calibration]).isdisjoint(set(np.array(groups)[tune]))
    known = {"fit": fit, "calibration": [validation[i] for i in calibration], "tune": [validation[i] for i in tune],
             "manual": [row for row, _ in partitions["manual"]], "real": [row for row, _ in partitions["real"]]}
    y = {key: np.array([row.label for row in rows]) for key, rows in known.items()}
    old = server.email_model()
    raw = lambda rows: old.predict_proba([row.body for row in rows])[:, list(old.classes_).index(1)]
    legacy_th = choose_threshold(y["tune"], raw(known["tune"]), raw(authored_ham))
    models = {}
    report = {"audit": usual_dict(audits), "partitions": usual_dict(counts),
              "calibration_counts": dict(Counter(int(n) for n in y["calibration"])),
              "threshold_counts": dict(Counter(int(n) for n in y["tune"])),
              "selection_budget": FALSE_POSITIVE_BUDGET, "models": {}, "current_policy": {}}

    fit_frames = {key: frame(known[key], context=True) for key in ("fit", "calibration", "tune")}
    short = frame(authored_ham, context=True)
    models["legacy"] = (old, raw, legacy_th)
    char = lambda: TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                  sublinear_tf=True, max_features=35000)
    trials = [
        ("word_lr", word_features, LogisticRegression(C=1, max_iter=700)),
        ("word_lr_balanced", word_features, LogisticRegression(C=2, class_weight="balanced", max_iter=700)),
        ("char_lr", char, LogisticRegression(C=2, class_weight="balanced", max_iter=700)),
        ("word_char_lr", mixed_features, LogisticRegression(C=2, class_weight="balanced", max_iter=700)),
        ("word_char_svm", mixed_features, LinearSVC(C=.5, class_weight="balanced", random_state=27)),
        ("hybrid_lr", mixed_features, LogisticRegression(C=.8, class_weight="balanced", max_iter=700)),
    ]
    cols = [c for c in fit_frames["fit"] if c != "text"]
    for name, vectorizer, estimator in trials:
        transforms = [("text", vectorizer(), "text")]
        if name == "hybrid_lr":
            transforms.append(("evidence", MaxAbsScaler(), cols))
        model = make_pipeline(ColumnTransformer(transforms), estimator).fit(fit_frames["fit"], y["fit"])
        model = CalibratedClassifierCV(FrozenEstimator(model), method="sigmoid").fit(fit_frames["calibration"], y["calibration"])
        probability = lambda table, m=model: m.predict_proba(table)[:, list(m.classes_).index(1)]
        cutoff = choose_threshold(y["tune"], probability(fit_frames["tune"]), probability(short))
        models[name] = (model, probability, cutoff)
        joblib.dump(model, args.output / f"{name}.joblib", compress=3)
        print(name, "locked threshold", round(cutoff, 7), flush=True)

    def inputs(name, cohort):
        if name == "legacy":
            return known[cohort]
        if cohort not in fit_frames:
            fit_frames[cohort] = frame(known[cohort], context=True)
        return fit_frames[cohort]
    selection = {}
    for name, (_, predict, threshold) in models.items():
        probability = predict(inputs(name, "tune"))
        selection[name] = score_set(y["tune"], probability, threshold)
    selected = max(selection, key=lambda name: (selection[name]["recall"], selection[name]["f1"], -selection[name]["fpr"]))
    report["selected_on_validation"] = selected
    print("Locked selection", selected, flush=True)

    for name, (_, predict, threshold) in models.items():
        model_path = ROOT / "models/email_phishing_model.joblib" if name == "legacy" else args.output / f"{name}.joblib"
        metrics = {"model_bytes": model_path.stat().st_size}
        for cohort in ("tune", "manual", "real"):
            rows = inputs(name, cohort)
            start = perf_counter()
            probability = predict(rows)
            latency = (perf_counter() - start) * 1000 / len(rows)
            result = score_set(y[cohort], probability, threshold, raw=True)
            result["fixed_half"] = score_set(y[cohort], probability, .5)
            result["batch_ms_per_message"] = latency
            if cohort == "tune":
                result["sweep"] = {str(t): score_set(y[cohort], probability, t) for t in (.25, .5, .6, .7, .8, .9, .95, .98)}
            metrics[cohort] = result
        inputs_short = authored_ham if name == "legacy" else short
        metrics["authored_tune_ham"] = {"count": len(authored_ham), "alerts": int(np.sum(predict(inputs_short) > threshold))}
        report["models"][name] = metrics

    for cohort in ("tune", "manual", "real"):
        rows = known[cohort]
        start = perf_counter()
        outputs = [server.predict_email_risk(row.body, row.sender, row.links, row.subject, row.reply_to) for row in rows]
        elapsed = (perf_counter() - start) * 1000 / len(rows)
        wanted = [output["risk_level"] == "suspicious" for output in outputs]
        summary = evaluate(y[cohort], wanted)
        summary["verdicts"] = {f"{label}_{status}": count for (label, status), count in
                               Counter((row.label, out["display_level"]) for row, out in zip(rows, outputs)).items()}
        summary["coverage"] = np.mean([o["display_level"] != "unknown" for o in outputs])
        summary["abstention_rate"] = 1 - summary["coverage"]
        summary["mean_ms_per_message"] = elapsed
        summary["unavailable"] = sum(not o["ml_evaluated"] for o in outputs)
        report["current_policy"][cohort] = summary
        # Also measure a policy that preserves evidence-based alerts and adds the
        # validation-selected learned alerts. Never tune this using final labels.
        prediction = models[selected][1](inputs(selected, cohort))
        promoted = [old_alert or p > models[selected][2] for old_alert, p in zip(wanted, prediction)]
        report.setdefault("alert_union", {})[cohort] = evaluate(y[cohort], promoted) | {
            "additional_alerts": sum(new and not before for new, before in zip(promoted, wanted)),
            "abstention_rate": np.mean([out["display_level"] == "unknown" and not alert
                                        for out, alert in zip(outputs, promoted)])}
    if args.archived_candidates:
        paths = args.archived_candidates
        report["archived_candidates"] = {}
        keys = {"sentinel-v2-email-63287d9": ("word_lr", "word_char_lr", "word_char_svm_calibrated"),
                "sentinel-main-email-final": ("word", "char", "context")}
        for folder, names in keys.items():
            for name in names:
                path = paths / folder / f"{name}.joblib"
                if not path.is_file():
                    continue
                # Read only known artifacts previously produced in this workspace.
                model = joblib.load(path)
                result = {"model_bytes": path.stat().st_size}
                for cohort in ("manual", "real"):
                    rows = known[cohort]
                    values = frame(rows)["text"] if folder.startswith("sentinel-v2") else [f"{r.subject}\n{r.body}" for r in rows]
                    if name == "context":
                        values = [server.email_features(email_evidence(r.body, r.sender, r.links, r.subject, r.reply_to)) for r in rows]
                    start = perf_counter()
                    p = model.predict_proba(values)[:, list(model.classes_).index(1)]
                    result[cohort] = score_set(y[cohort], p, .5, raw=True) | {"batch_ms_per_message": (perf_counter()-start)*1000/len(rows)}
                report["archived_candidates"][folder + "/" + name] = result
    paths = sorted(args.source_dir.iterdir()) + sorted(args.ham_dir.glob("*.tar.bz2"))
    if args.legacy_csv:
        paths.append(args.legacy_csv)
    report["input_sha256"] = {}
    for path in paths:
        with path.open("rb") as source:
            report["input_sha256"][path.name] = file_digest(source, "sha256").hexdigest()
    (args.output / "evaluation.json").write_text(json.dumps(report, indent=2, default=float) + "\n")


def usual_dict(counters):
    return {name: dict(counts) for name, counts in counters.items()}


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("source_dir", type=Path)
    cli.add_argument("ham_dir", type=Path)
    cli.add_argument("output", type=Path)
    cli.add_argument("--legacy-csv", type=Path)
    cli.add_argument("--public-seeds", action="store_true",
                     help="Use English non-Manual PhishFuzzer seeds in fit after cross-partition deduplication.")
    cli.add_argument("--archived-candidates", type=Path)
    main(cli.parse_args())
