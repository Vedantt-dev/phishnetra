"""Layer ablation study of the full PhishNetra decision pipeline.

Scores the held-out test split (same deterministic split as training) through the real
layers and the zero-trust policy engine, enabling different subsets of layers, and reports
detection metrics at the WARN and BLOCK operating points plus ROC-AUC of the fused risk.

    python ml/evaluate.py --data seed
    python ml/evaluate.py --data phiusiil --sample 20000   # also evaluates the DOM layer
"""
import argparse
import os

os.environ["PHISHNETRA_OFFLINE"] = "1"   # no WHOIS/TLS lookups: reproducible, offline evaluation

import numpy as np  # noqa: E402

from common import metrics, plot_curves, save_report  # noqa: E402
from datasets import split, url_dataset  # noqa: E402

from app.config import get_config  # noqa: E402
from app.features.dom_features import DOM_FEATURE_NAMES, complete_dom_features, dom_matrix  # noqa: E402
from app.layers import brand, dom_model, reputation, url_model  # noqa: E402
from app.layers.base import LayerResult  # noqa: E402
from app.policy import decide  # noqa: E402

ABLATIONS = {
    "reputation_only": ["reputation"],
    "url_model_only": ["url_model"],
    "brand_only": ["brand"],
    "url+reputation": ["url_model", "reputation"],
    "url_stage (rep+url+brand)": ["reputation", "url_model", "brand"],
    "dom_model_only": ["dom_model"],
    "full (all 4 layers)": ["reputation", "url_model", "dom_model", "brand"],
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="seed", choices=["seed", "phiusiil", "both"])
    ap.add_argument("--sample", type=int, default=0)
    args = ap.parse_args()

    _, test = split(url_dataset(args.data, args.sample))
    urls, y = test.url.tolist(), test.phishing.values
    has_dom = all(c in test.columns for c in DOM_FEATURE_NAMES if c not in ("HasTitle",))
    print(f"evaluating {len(test)} test rows (dom features: {has_dom})")

    model = url_model.load_model()
    url_scores = model.predict_proba(urls)[:, 1] * 100 if model else None
    dom_scores = None
    if has_dom and dom_model.load_model():
        rows = [complete_dom_features(u, str(t) if isinstance(t, str) else "", r)
                for u, t, r in zip(urls, test.get("Title", [""] * len(test)), test.to_dict("records"))]
        rf = dom_model.load_model()["model"]
        dom_scores = rf.predict_proba(dom_matrix(rows))[:, list(rf.classes_).index(1)] * 100

    per_row = []
    for i, u in enumerate(urls):
        title = test.iloc[i].get("Title", "") if "Title" in test.columns else ""
        title = title if isinstance(title, str) else ""
        layers = {
            "reputation": reputation.analyze(u, network=False),
            "url_model": LayerResult("url_model", float(url_scores[i])) if url_scores is not None else url_model.analyze(u),
            "brand": brand.analyze(u, title=title,
                                   has_password=bool(test.iloc[i].get("HasPasswordField", 0))),
        }
        if dom_scores is not None:
            layers["dom_model"] = LayerResult("dom_model", float(dom_scores[i]))
        per_row.append((layers, bool(test.iloc[i].get("HasPasswordField", 0))))

    th = get_config()["thresholds"]
    results, curves = {}, {}
    for name, names in ABLATIONS.items():
        if "dom_model" in names and dom_scores is None:
            continue
        risks, verdicts = [], []
        for layers, has_pw in per_row:
            d = decide([layers[n] for n in names], has_credential_form=has_pw)
            risks.append(d.risk)
            verdicts.append(d.verdict)
        risks = np.array(risks)
        results[name] = {
            "flagged_at_warn": metrics(y, risks / 100, threshold=th["warn"] / 100),
            "blocked_at_block": metrics(y, risks / 100, threshold=th["block"] / 100),
            "verdict_counts": {v: int(sum(1 for x in verdicts if x == v)) for v in ("ALLOW", "WARN", "RESTRICT", "BLOCK")},
        }
        curves[name] = risks / 100
        r = results[name]["flagged_at_warn"]
        print(f"{name:28s} AUC={r['roc_auc']:.4f} F1@warn={r['f1']:.4f} FPR@warn={r['false_positive_rate']:.4f} "
              f"recall@block={results[name]['blocked_at_block']['recall']:.4f}")

    report_name = f"ablation_{args.data}"
    save_report(report_name, {"dataset": args.data, "test_rows": len(test), "thresholds": th, "ablations": results})
    full = "full (all 4 layers)" if "full (all 4 layers)" in curves else "url_stage (rep+url+brand)"
    ordered = {full: curves.pop(full), **curves}
    plot_curves(report_name, y, ordered)
    print("wrote ml/reports/%s.{json,png}" % report_name)


if __name__ == "__main__":
    main()
