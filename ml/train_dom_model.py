"""Train the Layer-3 DOM / page-structure Random Forest on PhiUSIIL-style HTML features.

    python ml/train_dom_model.py --data seed
    python ml/train_dom_model.py --data phiusiil
"""
import argparse
from datetime import datetime, timezone

import joblib
from sklearn.ensemble import RandomForestClassifier

from common import MODELS_DIR, metrics, plot_curves, save_report
from datasets import dom_dataset, split

from app.features.dom_features import DOM_FEATURE_NAMES  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="seed", choices=["seed", "phiusiil"])
    ap.add_argument("--sample", type=int, default=0)
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()

    df = dom_dataset(args.data, args.sample)
    train, test = split(df)
    X_train, X_test = train[DOM_FEATURE_NAMES].values, test[DOM_FEATURE_NAMES].values
    print(f"dataset={args.data} rows={len(df)} train={len(train)} test={len(test)}")

    model = RandomForestClassifier(n_estimators=300, min_samples_leaf=5, class_weight="balanced",
                                   n_jobs=-1, random_state=42)
    model.fit(X_train, train.phishing.values)
    proba = model.predict_proba(X_test)[:, 1]
    importances = sorted(zip(DOM_FEATURE_NAMES, model.feature_importances_), key=lambda kv: -kv[1])
    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report = {
        "model": "dom_random_forest",
        "dataset": args.data,
        "trained_at": trained_at,
        "train_rows": len(train),
        "test": metrics(test.phishing.values, proba),
        "feature_importance": {k: round(float(v), 4) for k, v in importances},
    }
    name = f"dom_model_{args.data}"
    save_report(name, report)
    plot_curves(name, test.phishing.values, {"Random Forest": proba})
    print("test:", report["test"])

    if not args.no_save:
        bundle = {"model": model, "features": DOM_FEATURE_NAMES, "version": f"{args.data}-{trained_at}",
                  "dataset": args.data, "test_metrics": report["test"]}
        joblib.dump(bundle, MODELS_DIR / "dom_model.joblib", compress=3)
        print("saved", MODELS_DIR / "dom_model.joblib")


if __name__ == "__main__":
    main()
