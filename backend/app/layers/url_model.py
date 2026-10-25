"""Layer 2 — URL lexical machine-learning model.

Ensemble of (a) logistic regression over character n-gram TF-IDF + scaled lexical
features and (b) histogram gradient boosting over lexical features. Trained by
ml/train_url_model.py; falls back to a transparent rule score if no model is present.
"""
import logging
from functools import lru_cache
from typing import Optional

import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from app.config import MODELS_DIR
from app.features.url_features import explain_url, extract_url_features, feature_matrix, url_text
from app.layers.base import LayerResult

log = logging.getLogger(__name__)
MODEL_PATH = MODELS_DIR / "url_model.joblib"


def build_lr_pipeline(max_features: int = 100_000) -> Pipeline:
    text = Pipeline([
        ("text", FunctionTransformer(url_text)),
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2,
                                  max_features=max_features, sublinear_tf=True)),
    ])
    lexical = Pipeline([("fx", FunctionTransformer(feature_matrix)), ("scale", StandardScaler())])
    return Pipeline([
        ("features", FeatureUnion([("ngrams", text), ("lexical", lexical)])),
        ("clf", LogisticRegression(C=4.0, max_iter=3000, class_weight="balanced")),
    ])


def build_gb_pipeline() -> Pipeline:
    return Pipeline([
        ("fx", FunctionTransformer(feature_matrix)),
        ("clf", HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, random_state=42)),
    ])


class URLEnsemble:
    """Soft-voting wrapper; picklable so ml/ can save it and the API can load it."""

    def __init__(self, lr: Pipeline, gb: Pipeline, lr_weight: float = 0.5, meta: Optional[dict] = None):
        self.lr, self.gb, self.lr_weight, self.meta = lr, gb, lr_weight, meta or {}

    def fit(self, urls, y):
        self.lr.fit(urls, y)
        self.gb.fit(urls, y)
        return self

    def predict_proba(self, urls):
        return self.lr_weight * self.lr.predict_proba(urls) + (1 - self.lr_weight) * self.gb.predict_proba(urls)


@lru_cache(maxsize=1)
def load_model() -> Optional[URLEnsemble]:
    if not MODEL_PATH.exists():
        log.warning("URL model not found at %s — using rule-based fallback", MODEL_PATH)
        return None
    return joblib.load(MODEL_PATH)


def _rule_score(f) -> float:
    score = 10.0
    score += 30 * f["has_ip"] + 25 * f["has_at"] + 25 * f["has_punycode"] + 20 * f["suspicious_tld"]
    score += min(f["keyword_hits"], 4) * 8 + 15 * f["tld_in_path"] + 10 * f["is_free_hosting"]
    score += 10 * (f["num_subdomains"] >= 3) + 10 * (f["url_length"] > 100) + 5 * (f["hyphen_in_host"] >= 2)
    score += 10 * (not f["is_https"])
    return min(100.0, score)


def analyze(url: str) -> LayerResult:
    features = extract_url_features(url)
    reasons = explain_url(features)
    model = load_model()
    if model is None:
        score = _rule_score(features)
        details = {"engine": "rules"}
    else:
        score = float(model.predict_proba([url])[0][1] * 100)
        details = {"engine": "ml-ensemble", "model_version": model.meta.get("version", "unknown")}
    if score >= 50:
        reasons.insert(0, f"URL classifier rates this {score:.0f}% likely phishing")
    elif not reasons:
        reasons.append("No suspicious lexical patterns in the URL")
    details["features"] = {k: round(v, 3) for k, v in features.items()}
    return LayerResult(name="url_model", score=round(score, 2), reasons=reasons, details=details)
