"""Export the installed sklearn models and their feature contract. No fitting."""
from hashlib import sha256
from importlib.resources import files
import json
from pathlib import Path
import shutil

from backend import assessments, server

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "extension/public/models"


def feature_key(term):
    # Two deterministic unsigned hashes keep training vocabulary out of plain text.
    # This representation is not encryption.
    a, b = 2166136261, 5381
    for c in term:
        a = ((a ^ ord(c)) * 16777619) & 0xffffffff
        b = (b * 33 + ord(c)) & 0xffffffff
    return f"{a:08x}{b:08x}"


def export():
    model = server.email_model()
    vectorizer, linear = (step for _, step in model.steps)
    assert list(linear.classes_) == [0, 1]
    assert (vectorizer.ngram_range, vectorizer.norm, vectorizer.sublinear_tf, vectorizer.token_pattern,
            vectorizer.lowercase, vectorizer.stop_words, vectorizer.strip_accents, vectorizer.analyzer) == (
                (1, 2), "l2", False, r"(?u)\b\w\w+\b", True, None, None, "word")
    terms = {feature_key(t): [float(vectorizer.idf_[i]), float(linear.coef_[0, i])]
             for t, i in vectorizer.vocabulary_.items()}
    assert len(terms) == len(vectorizer.vocabulary_)
    model_url = server.candidate()
    assert list(model_url.classes_) == [0, 1] and (model_url.is_categorical_ is None or not model_url.is_categorical_.any())
    trees = []
    for tree, in model_url._predictors:
        trees.append([[int(n["feature_idx"]), float(n["num_threshold"]), int(n["left"]), int(n["right"])]
                      if not n["is_leaf"] else [float(n["value"])] for n in tree.nodes])
    regex_names = ("CREDENTIAL_REQUEST", "PRESSURE", "PAYMENT", "ACTION", "VERIFY", "NEGATION", "SECURITY_NOTICE")
    filenames = ("email_phishing_model.joblib", "url_context_candidate.joblib")
    config = {"version": 1, "sha256": {f: sha256((ROOT / "models" / f).read_bytes()).hexdigest() for f in filenames},
              "email": {"intercept": float(linear.intercept_[0]), "terms": terms},
              "url": {"intercept": float(model_url._baseline_prediction.item()), "trees": trees,
                      "columns": model_url.feature_names_in_.tolist()},
              "patterns": {k: getattr(assessments, k).pattern for k in regex_names},
              "brands": assessments.BRANDS, "shorteners": sorted(assessments.SHORTENERS)}
    DEST.mkdir(exist_ok=True, parents=True)
    (DEST / "screening.json").write_text(json.dumps(config, separators=(",", ":"), ensure_ascii=True) + "\n")
    shutil.copyfile(files("tldextract").joinpath(".tld_set_snapshot"), DEST / "public_suffix_list.dat")


if __name__ == "__main__":
    export()
