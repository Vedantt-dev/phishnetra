"""Train the Layer-2 URL ensemble (char n-gram LR + lexical gradient boosting).

    python ml/train_url_model.py --data seed            # bundled synthetic seed (no download)
    python ml/train_url_model.py --data phiusiil --cv   # real dataset, with 5-fold CV
    python ml/train_url_model.py --data both
"""
import argparse
import time
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.model_selection import StratifiedKFold, cross_val_score

from common import MODELS_DIR, metrics, plot_curves, save_report
from datasets import split, url_dataset

from app.layers.url_model import URLEnsemble, build_gb_pipeline, build_lr_pipeline  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="seed", choices=["seed", "phiusiil", "both"])
    ap.add_argument("--sample", type=int, default=0, help="balanced subsample size (0 = all rows)")
    ap.add_argument("--cv", action="store_true", help="also run 5-fold stratified CV on the training split")
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()

    df = url_dataset(args.data, args.sample)
    train, test = split(df)
    print(f"dataset={args.data} rows={len(df)} phishing={int(df.phishing.sum())} train={len(train)} test={len(test)}")

    model = URLEnsemble(build_lr_pipeline(), build_gb_pipeline())
    t0 = time.time()
    model.fit(train.url.tolist(), train.phishing.values)
    train_seconds = time.time() - t0

    urls, y = test.url.tolist(), test.phishing.values
    t0 = time.time()
    p_ens = model.predict_proba(urls)[:, 1]
    latency_ms = (time.time() - t0) / len(urls) * 1000
    p_lr, p_gb = model.lr.predict_proba(urls)[:, 1], model.gb.predict_proba(urls)[:, 1]

    report = {
        "model": "url_ensemble",
        "dataset": args.data,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "train_rows": len(train),
        "train_seconds": round(train_seconds, 1),
        "inference_ms_per_url": round(latency_ms, 3),
        "test": {
            "ensemble": metrics(y, p_ens),
            "char_ngram_logreg": metrics(y, p_lr),
            "lexical_gradient_boosting": metrics(y, p_gb),
        },
    }
    if args.cv:
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        scores = cross_val_score(build_lr_pipeline(), np.array(train.url.tolist(), dtype=object),
                                 train.phishing.values, cv=cv, scoring="f1", n_jobs=-1)
        report["cv_f1_logreg"] = {"mean": round(float(scores.mean()), 4), "std": round(float(scores.std()), 4)}

    name = f"url_model_{args.data}"
    save_report(name, report)
    plot_curves(name, y, {"Ensemble": p_ens, "Char n-gram LR": p_lr, "Lexical GB": p_gb})
    print("ensemble:", report["test"]["ensemble"])

    if not args.no_save:
        model.meta = {"version": f"{args.data}-{report['trained_at']}", "dataset": args.data,
                      "test_metrics": report["test"]["ensemble"]}
        MODELS_DIR.mkdir(exist_ok=True)
        joblib.dump(model, MODELS_DIR / "url_model.joblib", compress=3)
        print("saved", MODELS_DIR / "url_model.joblib")


if __name__ == "__main__":
    main()
