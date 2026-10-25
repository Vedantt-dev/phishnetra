"""Shared helpers for the training / evaluation scripts."""
import json
import sys
import warnings
from pathlib import Path

import numpy as np

ML_DIR = Path(__file__).resolve().parent
PROJECT_DIR = ML_DIR.parent
BACKEND_DIR = PROJECT_DIR / "backend"
DATASETS_DIR = ML_DIR / "datasets"
REPORTS_DIR = ML_DIR / "reports"
SEED_DIR = BACKEND_DIR / "data"
MODELS_DIR = BACKEND_DIR / "models"

warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")

# Make the backend package importable so training and serving share feature code.
sys.path.insert(0, str(BACKEND_DIR))

PHIUSIIL_CSV = DATASETS_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"


def load_phiusiil():
    """PhiUSIIL labels legitimate=1, phishing=0; we flip so phishing is the positive class."""
    import pandas as pd

    if not PHIUSIIL_CSV.exists():
        raise SystemExit(f"{PHIUSIIL_CSV} missing — run: python ml/download_datasets.py --phiusiil")
    df = pd.read_csv(PHIUSIIL_CSV)
    df["phishing"] = 1 - df["label"].astype(int)
    return df


def metrics(y_true, proba, threshold: float = 0.5) -> dict:
    from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                                 precision_score, recall_score, roc_auc_score)

    pred = (np.asarray(proba) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "n": int(len(y_true)),
        "accuracy": round(float(accuracy_score(y_true, pred)), 4),
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, proba)), 4),
        "pr_auc": round(float(average_precision_score(y_true, proba)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if fp + tn else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def save_report(name: str, payload: dict) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2))
    return path


def plot_curves(name: str, y_true, curves: dict) -> Path:
    """ROC curves + confusion matrix of the first curve, saved as one PNG."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import ConfusionMatrixDisplay, roc_curve

    fig, (ax_roc, ax_cm) = plt.subplots(1, 2, figsize=(11, 4.5))
    for label, proba in curves.items():
        fpr, tpr, _ = roc_curve(y_true, proba)
        ax_roc.plot(fpr, tpr, label=label)
    ax_roc.plot([0, 1], [0, 1], "--", color="grey", linewidth=0.8)
    ax_roc.set(xlabel="False positive rate", ylabel="True positive rate", title=f"ROC — {name}")
    ax_roc.legend(loc="lower right", fontsize=8)
    first = next(iter(curves.values()))
    ConfusionMatrixDisplay.from_predictions(y_true, (np.asarray(first) >= 0.5).astype(int),
                                            display_labels=["legit", "phish"], ax=ax_cm, colorbar=False)
    ax_cm.set_title(f"Confusion matrix — {next(iter(curves))}")
    fig.tight_layout()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"{name}.png"
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path
