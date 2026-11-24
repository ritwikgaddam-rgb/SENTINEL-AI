"""Local screening scores. Model outputs and evidence scores are reported separately."""
from functools import lru_cache
from math import isfinite, prod
from pathlib import Path


@lru_cache(maxsize=1)
def email_model():
    try:
        import joblib

        model = joblib.load(Path(__file__).resolve().parents[1] / "models/email_phishing_model.joblib")
        if set(model.classes_) != {0, 1} or not callable(model.predict_proba):
            return None
        return model
    except Exception:
        # A missing, incompatible, or corrupt local artifact is surfaced in API health.
        return None


def model_observation(model, rows, positive_class, name):
    unavailable = {"status": "unavailable", "model": name, "message": "Local model prediction is unavailable."}
    try:
        index = list(model.classes_).index(positive_class)
        probabilities = model.predict_proba(rows)[:, index]
    except Exception:
        return [unavailable.copy() for _ in range(len(rows))]
    return [
        {"status": "flagged" if score > 0.5 else "not_flagged", "model": name,
         "phishing_probability": float(score), "prediction": "phishing" if score > 0.5 else "legitimate",
         "message": "Local model flagged this input." if score > 0.5 else "Local model did not flag this input."}
        if isfinite(score) and 0 <= score <= 1 else unavailable.copy()
        for score in probabilities
    ]


def apply_score(result, observation, weight, enough=True, link_probability=0, model_only_caution=False):
    """Use the learned signal as part of the index, bounded by independent evidence."""
    strength = {"low": 0.06, "medium": 0.27, "high": 0.91, "danger": 0.91}
    independent = {}
    for item in result["markers"]:
        category = item["category"]
        weight_for_marker = .06 if item["id"] == "insecure_http" else strength.get(item["severity"], 0)
        independent[category] = max(independent.get(category, 0), weight_for_marker)
    evidence = 1 - prod(1 - value for value in independent.values())
    confirmed = result["risk_level"] == "suspicious"
    if confirmed:
        evidence = max(evidence, 0.91)
    if evidence >= .27:
        writing = result.get("grammar", {}).get("per_100_words") or 0
        evidence += (1 - evidence) * min(writing / 100, .06)

    probability = observation.get("phishing_probability")
    risk = None
    result["model_observation"] = observation
    result["ml_evaluated"] = probability is not None
    if probability is not None and (enough or confirmed):
        learned = max(probability, .55 * link_probability)
        risk = round(100 * (evidence + (1 - evidence) * weight * learned), 1)
    if confirmed or risk is not None and evidence >= .27 and risk >= 58:
        level, label, display = "suspicious", "Suspicious", "danger"
        explanation = "The assessment found phishing indicators. Verify unexpected requests independently."
    elif risk is not None and ((evidence >= .27 and risk >= 40)
                               or (model_only_caution and observation["status"] == "flagged")):
        level, label, display = "suspicious", "Caution advised", "suspicious"
        explanation = "The available model and structural signals warrant a closer look."
    elif probability is None:
        level, label, display = "uncertain", "Analysis unavailable", "unknown"
        explanation = "The local model did not provide a valid prediction. Evidence findings are shown separately."
    elif risk is None:
        level, label, display = "uncertain", "Insufficient information", "unknown"
        explanation = "The message lacks enough context for a screening score."
    else:
        level, label, display = "neutral", "No clear phishing indicators detected", "safe"
        explanation = "The score summarizes the available signals. Verify unexpected requests independently."
    if confirmed and probability is None:
        explanation += " The local model is unavailable."
    result.update(risk_level=level, assessment=label, display_level=display, explanation=explanation,
                  risk_score=risk, safety_score=round(100-risk, 1) if risk is not None else None,
                  prediction=observation.get("prediction"), confidence=None)
    return result
