"""Dataset loading with deterministic train/test splits shared by train and evaluate."""
import pandas as pd
from sklearn.model_selection import train_test_split

from common import SEED_DIR, load_phiusiil

SPLIT_SEED = 42


def url_dataset(name: str, sample: int = 0) -> pd.DataFrame:
    """Columns: url, phishing (+ PhiUSIIL HTML features when available)."""
    frames = []
    if name in ("seed", "both"):
        frames.append(pd.read_csv(SEED_DIR / "seed_urls.csv"))
    if name in ("phiusiil", "both"):
        df = load_phiusiil().rename(columns={"URL": "url"})
        if sample:
            df = df.groupby("phishing", group_keys=False).apply(
                lambda g: g.sample(min(len(g), sample // 2), random_state=SPLIT_SEED))
        frames.append(df)
    if not frames:
        raise SystemExit(f"unknown dataset {name!r}")
    return pd.concat(frames, ignore_index=True).drop_duplicates("url").reset_index(drop=True)


def dom_dataset(name: str, sample: int = 0) -> pd.DataFrame:
    if name == "seed":
        return pd.read_csv(SEED_DIR / "seed_dom.csv")
    if name == "phiusiil":
        return url_dataset("phiusiil", sample)
    raise SystemExit(f"unknown dataset {name!r}")


def split(df: pd.DataFrame, test_size: float = 0.2):
    return train_test_split(df, test_size=test_size, stratify=df["phishing"], random_state=SPLIT_SEED)
