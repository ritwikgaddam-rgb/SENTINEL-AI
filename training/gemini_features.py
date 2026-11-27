"""Research-only email features for the SentinelAI phishing study."""

from email.utils import parseaddr
import re
from urllib.parse import parse_qsl, unquote

import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import normalize

from backend.assessments import MAX_LINKS, QUOTED_LINES, SHORTENERS, credential_context, link_items, split_url
from training.compare_email_models import model_text
from training.email_recall_study import (
    ACTION_ANCHOR_PATTERNS,
    CALLBACK_PHISHING_PATTERN,
    OPEN_REDIRECT_PARAMS,
    WIRE_URGENCY_PATTERN,
    is_esp_domain,
)


# These services host ordinary documents and forms. A hosting match contributes
# only in combination with observed action language or a lure-shaped path.
SHARED_HOSTS = (
    "drive.google.com",
    "forms.gle",
    "forms.office.com",
    "forms.microsoft.com",
    "1drv.ms",
    "sharepoint.com",
    "dropbox.com",
    "github.io",
    "pages.dev",
    "workers.dev",
    "netlify.app",
    "vercel.app",
    "airtable.com",
    "typeform.com",
    "onedrive.live.com",
    "canva.com",
    "notion.site",
    "webflow.io",
    "linktr.ee",
    "firebasestorage.googleapis.com",
    "storage.googleapis.com",
    "blob.core.windows.net",
    "s3.amazonaws.com",
    "r2.dev",
)
ACTION_PATH = re.compile(r"(?:^|/)(?:login|sign[-_]?in|verify|auth|invoice|docs?|document)(?:[./_-]|$)", re.I)
AUTH_PATH = re.compile(r"(?:^|/)(?:login|sign[-_]?in|verify|auth)(?:[./_-]|$)", re.I)
EMAIL_VALUE = re.compile(r"[\w.+%-]+@[\w.-]+\.[a-z]{2,}", re.I)
OPAQUE_VALUE = re.compile(r"(?=.*[A-Za-z])(?=.*[\d_+/-])[A-Za-z0-9_+/-]{28,}={0,2}$")
ENCODED_TOKEN = re.compile(r"(?:[A-Za-z0-9_-]{12,}\.){2}[A-Za-z0-9_-]{12,}")
BARE_HOST = re.compile(
    r"(?<![\w@])(?:[\w-]+\.)+(?:com|net|org|io|gov|edu|app|co|dev|in)(?=[^\w.]|$)(?:/[^\s<>]*)?", re.I
)
NEWSLETTER = re.compile(
    r"\b(?:unsubscribe|manage (?:email|subscription) preferences|view (?:this )?in (?:your )?browser)\b", re.I
)
TRANSACTION = re.compile(
    r"\b(?:receipt|invoice|order confirmation|shipment|tracking number|payment confirmation)\b", re.I
)
TRANSACTION_DETAILS = re.compile(
    r"\b(?:order (?:number|total)|invoice (?:number|date)|shipping address|subtotal|delivery date|payment method|transaction (?:date|id))\b",
    re.I,
)
REPLY_PREFIX = re.compile(r"^\s*(?:re|fw|fwd)\s*:", re.I)
REPLY_LINE = re.compile(r"^(?:[ \t]*>|On [^\n]{1,300} wrote:\s*$)", re.I | re.M)
REFUND_CONTEXT = re.compile(
    r"\b(?:refund|cancel(?:lation)?|charge[ds]?|subscription|billing|invoice)\b", re.I
)
CALL_ACTION = re.compile(r"\b(?:call|phone|dial|contact (?:our )?support)\b", re.I)
DELIVERY_CONTEXT = re.compile(r"\b(?:delivery|package|parcel|account|subscription)\b", re.I)
URGENCY = re.compile(
    r"\b(?:urgent(?:ly)?|immediately|today|within \d+ (?:minutes?|hours?)|final notice|same[- ]day)\b", re.I
)
VALUE_ACTION = re.compile(r"\b(?:send|wire|transfer|pay|purchase|buy|update|change)\b", re.I)
LEGACY_HAM_SOURCES = frozenset(
    {
        "20021010_easy_ham.tar.bz2",
        "20021010_hard_ham.tar.bz2",
        "20030228_easy_ham.tar.bz2",
        "20030228_hard_ham.tar.bz2",
        "20030228_easy_ham_2.tar.bz2",
    }
)
MODERN_HAM_SOURCES = frozenset({"Keycloak templates", "allauth template", "Solidus strings"})
VIEW_WORDS = 80


def _anchors(row, links):
    """Use the same local destination parser and bounds as the current scanner."""
    if links is not None:
        return links
    _, anchors, _ = link_items(row.body, "", row.links)
    return tuple({"url": item["url"], "label": item["display_text"]} for item in anchors)


def _query_fields(query):
    try:
        return parse_qsl(query, max_num_fields=50, errors="replace")
    except ValueError:
        return ()


def _observed_destinations(url):
    """Inspect a URL and bounded nested URL parameters without visiting them."""
    pending = [(url, 0)]
    seen = set()
    while pending and len(seen) < 6:
        candidate, depth = pending.pop(0)
        if not isinstance(candidate, str) or candidate in seen:
            continue
        seen.add(candidate)
        try:
            parts, host, _ = split_url(candidate)
        except (ValueError, UnicodeError):
            continue
        query = _query_fields(parts.query)
        yield parts, host, query, depth
        if depth == 2:
            continue
        for key, value in query:
            if key.casefold() not in OPEN_REDIRECT_PARAMS:
                continue
            # parse_qsl decodes one layer. Bound any additional decoding and
            # accept only web destinations that the existing parser validates.
            for _ in range(2):
                if value.casefold().startswith(("https://", "http://")):
                    pending.append((value, depth + 1))
                    break
                value = unquote(value)


def compute_deconfounded_sample_weights(rows, legacy_ham_weight=0.6, modern_ham_weight=3.0):
    """Use fit-only source and format weights with mean one to preserve LR scale."""
    if (
        not np.isfinite([legacy_ham_weight, modern_ham_weight]).all()
        or min(legacy_ham_weight, modern_ham_weight) <= 0
    ):
        raise ValueError("Sample weight ratios must be finite and positive.")
    weights = np.ones(len(rows))
    for index, row in enumerate(rows):
        if row.label != 0:
            continue
        if row.source in LEGACY_HAM_SOURCES:
            weights[index] = legacy_ham_weight
        elif row.source in MODERN_HAM_SOURCES or _modern_format(row):
            weights[index] = modern_ham_weight
    return weights / weights.mean() if len(weights) else weights


def _modern_format(row):
    body = QUOTED_LINES.sub("", row.body)
    # Require a transaction and its details or a bulk-mail footer plus a URL.
    return bool(
        (TRANSACTION.search(row.subject) and TRANSACTION_DETAILS.search(body))
        or (NEWSLETTER.search(body) and (row.links or "https://" in body))
    )


def extract_lots_and_url_lure_features(row, links=None):
    """Record destination and message structure as observed binary features."""
    anchors = _anchors(row, links)
    body = QUOTED_LINES.sub("", row.body)
    single_link_cta = len(anchors) == 1 and ACTION_ANCHOR_PATTERNS.search(f"{row.subject}\n{body}")
    features = dict.fromkeys(
        (
            "abused_cloud_host_with_cta",
            "credential_or_invoice_path",
            "credential_path_lure",
            "prefilled_email_param",
            "opaque_query_param",
            "nested_link_lure",
            "tracking_link_observed",
        ),
        0,
    )
    for item in anchors[:MAX_LINKS]:
        url = item.get("url") if isinstance(item, dict) else item
        label = (item.get("label") or item.get("display_text", "")) if isinstance(item, dict) else ""
        cta = single_link_cta or ACTION_ANCHOR_PATTERNS.search(label)
        for parts, host, fields, depth in _observed_destinations(url):
            tracked = is_esp_domain(host)
            path = unquote(parts.path)
            shared = is_abused_cloud_host(host, path)
            lure = not tracked and bool(ACTION_PATH.search(path))
            features["tracking_link_observed"] |= int(tracked)
            features["abused_cloud_host_with_cta"] |= int(shared and bool(cta))
            features["credential_or_invoice_path"] |= int(lure)
            features["credential_path_lure"] |= int(not tracked and bool(AUTH_PATH.search(path)))
            features["prefilled_email_param"] |= int(
                not tracked and any(EMAIL_VALUE.fullmatch(v) for _, v in fields)
            )
            features["opaque_query_param"] |= int(
                not tracked and any(OPAQUE_VALUE.fullmatch(v) for _, v in fields)
            )
            features["nested_link_lure"] |= int(depth > 0 and (lure or (shared and bool(cta))))
    return features


def is_abused_cloud_host(host, path=""):
    """Recognize shared hosting used in both benign and malicious messages."""
    return (
        host in SHORTENERS
        or (host == "docs.google.com" and (path == "/forms" or path.startswith("/forms/")))
        or any(host == domain or host.endswith("." + domain) for domain in SHARED_HOSTS)
    )


def extract_benign_suppressor_features(row, links=None):
    """Expose ordinary-mail context as features for fit, without granting trust."""
    body = QUOTED_LINES.sub("", row.body)
    text = f"{row.subject}\n{body}"
    return {
        "newsletter_bulk_markers": int(bool(NEWSLETTER.search(body))),
        "transactional_receipt_markers": int(
            bool(TRANSACTION.search(text) and TRANSACTION_DETAILS.search(body))
        ),
        # Prefixes are self-attested. Pair with visible quoted conversation and
        # represent the result as a surface convention, never verified threading.
        "conversational_reply_markers": int(
            bool(REPLY_PREFIX.search(row.subject) and REPLY_LINE.search(row.body))
        ),
    }


def extract_sparse_header_short_features(row, links=None):
    """Record missing headers independently from short-message content cues."""
    body = QUOTED_LINES.sub("", row.body)
    text = f"{row.subject}\n{body}"
    no_links = not _anchors(row, links)
    short = len(text.split()) <= 30
    missing_sender = not parseaddr(row.sender)[1].rpartition("@")[2]
    missing_subject = not row.subject.strip()
    direct = any(credential_context(section)[0] == "credential_request" for section in (body, row.subject))
    return {
        "is_sparse_header_or_short": int(short or missing_sender or missing_subject),
        "is_short_message": int(short),
        "sender_missing": int(missing_sender),
        "subject_missing": int(missing_subject),
        "reply_to_missing": int(not parseaddr(row.reply_to)[1].rpartition("@")[2]),
        "short_callback_refund_scam": int(
            bool(
                short
                and no_links
                and CALLBACK_PHISHING_PATTERN.search(text)
                and CALL_ACTION.search(text)
                and REFUND_CONTEXT.search(text)
            )
        ),
        "short_sms_delivery_account_lure": int(
            bool(
                short
                and DELIVERY_CONTEXT.search(text)
                and (direct or (not no_links and ACTION_ANCHOR_PATTERNS.search(text)))
            )
        ),
        "short_linkless_bec_urgency": int(
            bool(
                short
                and no_links
                and URGENCY.search(text)
                and VALUE_ACTION.search(text)
                and WIRE_URGENCY_PATTERN.search(text)
            )
        ),
    }


def _masked_text(value):
    def mask_token(token):
        core = token.strip(".,:;()[]<>\"'")
        return "opaque value" if OPAQUE_VALUE.fullmatch(core) or ENCODED_TOKEN.fullmatch(core) else token

    unquoted = QUOTED_LINES.sub("", value)
    text = model_text(" ".join(mask_token(token) for token in unquoted.split()), "")
    text = BARE_HOST.sub("link", text)
    return (
        text.replace("urlplaceholder", "link")
        .replace("addressplaceholder", "email address")
        .replace("numberplaceholder", "number")
    )


def two_view_texts(row, links=None, *, include_middle=False):
    """Construct masked leading and trailing text, optionally with a center window."""
    body = _masked_text(row.body).split()
    subject = _masked_text(row.subject).split()[:16]
    labels = " ".join(
        (item.get("label") or item.get("display_text", ""))
        for item in _anchors(row, links)[:8]
        if isinstance(item, dict)
    )
    label_words = _masked_text(labels).split()[:16]
    leading = " ".join(subject + body[:VIEW_WORDS])
    trailing = " ".join(body[-VIEW_WORDS:] + label_words)
    if include_middle:
        start = max(0, (len(body) - VIEW_WORDS) // 2)
        return leading, trailing, " ".join(body[start : start + VIEW_WORDS])
    return leading, trailing


def compute_prototype_margin(embeddings, fit_ids, fit_labels, *, n_clusters=4, sample_weight=None):
    """Fit per-class cosine prototypes using only the designated fit rows."""
    vectors = normalize(np.asarray(embeddings, dtype=np.float32))
    fit_ids = np.asarray(fit_ids)
    fit_labels = np.asarray(fit_labels)
    if fit_ids.ndim != 1 or fit_labels.shape != fit_ids.shape or set(fit_labels) != {0, 1}:
        raise ValueError("Supply one binary label for each fit index and include both classes.")
    if np.unique(fit_ids).size != len(fit_ids) or fit_ids.min() < 0 or fit_ids.max() >= len(vectors):
        raise ValueError("Fit indices must be distinct indices into the embedding matrix.")
    if sample_weight is not None:
        sample_weight = np.asarray(sample_weight)
        if sample_weight.shape != fit_ids.shape:
            raise ValueError("Sample weights must align to fit rows.")
    prototypes, similarities = {}, {}
    for label in (0, 1):
        mask = fit_labels == label
        class_vectors = vectors[fit_ids[mask]]
        clusters = min(n_clusters, len(np.unique(class_vectors, axis=0)))
        weights = None if sample_weight is None else sample_weight[mask]
        clustering = KMeans(n_clusters=clusters, n_init=3, max_iter=120, random_state=42)
        clustering.fit(class_vectors, sample_weight=weights)
        prototypes[label] = normalize(clustering.cluster_centers_)
        similarities[label] = (vectors @ prototypes[label].T).max(axis=1)
    return similarities[1] - similarities[0], prototypes
