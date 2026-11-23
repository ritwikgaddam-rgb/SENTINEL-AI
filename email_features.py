"""Shared email text features for SentinelAI's *candidate* phishing classifier.

Generic conversational words and phrases are not standalone phishing evidence.
Context-bearing n-grams (e.g. "your password") are preserved.
Keep this module importable when loading the joblib pipeline.
"""

from sklearn.feature_extraction.text import TfidfVectorizer

# Do not include security-relevant terms such as password, otp, verify, link,
# payment, account, suspended, login, bank, transfer or urgent here.
GENERIC_WORDS = frozenset("""
a about am an and are as at be been by can could did do does doing evening
for from good had has have he hello her here hey hi him his how i in is it
its just like man me mine morning my night no not of ok okay on or our ours
please she should so some thanks thank that the their them there they this
to today us was we well were what when where who why will with would yes
you your yours
""".split())

# Uses sklearn's normal lowercase, Unicode accent stripping, word tokenization,
# and 1-2 word n-grams. The analyzer is a top-level function so joblib can load it.
_BASE_ANALYZER = TfidfVectorizer(
    ngram_range=(1, 2), strip_accents="unicode"
).build_analyzer()


def contextual_email_features(text):
    """Exclude generic-only features while preserving meaningful context."""
    return [
        feature for feature in _BASE_ANALYZER(text)
        if not all(token in GENERIC_WORDS for token in feature.split())
    ]
