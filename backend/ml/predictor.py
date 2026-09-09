from __future__ import annotations

from pathlib import Path
import json
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_DIR / "models"
MODEL_FILE = MODEL_DIR / "random_forest_export.json"
IMPORTANCE_FILE = MODEL_DIR / "feature_importance.csv"

if not MODEL_FILE.exists():
    raise FileNotFoundError(
        "Portable model export is missing: models/random_forest_export.json"
    )

_payload = json.loads(MODEL_FILE.read_text(encoding="utf-8"))
classes = np.array(_payload["classes"], dtype=object)
feature_columns = list(_payload["feature_columns"])
_trees = []
for tree in _payload["trees"]:
    _trees.append({
        "children_left": np.asarray(tree["children_left"], dtype=np.int32),
        "children_right": np.asarray(tree["children_right"], dtype=np.int32),
        "feature": np.asarray(tree["feature"], dtype=np.int32),
        "threshold": np.asarray(tree["threshold"], dtype=np.float64),
        "value": np.asarray(tree["value"], dtype=np.float64),
    })

try:
    _importance_df = pd.read_csv(IMPORTANCE_FILE)
except Exception:
    _importance_df = pd.DataFrame(columns=["Feature", "Importance"])


def prepare_features(df: pd.DataFrame) -> np.ndarray:
    """Return CICIDS features in the exact training order.

    This runtime intentionally uses a portable JSON export of the trained
    RandomForest instead of importing scikit-learn/scipy. That avoids the
    Windows scipy DLL/Application-Control failure that can otherwise stop the
    whole FastAPI backend from starting.
    """
    work = df.copy()
    work.columns = work.columns.str.strip()
    work = work.reindex(columns=feature_columns)
    for column in feature_columns:
        work[column] = pd.to_numeric(work[column], errors="coerce")
    work = work.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return work.to_numpy(dtype=np.float64, copy=False)


def _tree_proba_batch(tree: dict, X: np.ndarray) -> np.ndarray:
    n = X.shape[0]
    node = np.zeros(n, dtype=np.int32)
    active = np.ones(n, dtype=bool)

    # Trees in this trained model are shallow. A conservative cap prevents a
    # malformed export from creating an infinite loop.
    for _ in range(128):
        if not active.any():
            break
        active_idx = np.flatnonzero(active)
        current = node[active_idx]
        feat = tree["feature"][current]
        leaf_mask = feat < 0

        if leaf_mask.any():
            active[active_idx[leaf_mask]] = False

        branch_idx = active_idx[~leaf_mask]
        if branch_idx.size == 0:
            continue
        branch_nodes = node[branch_idx]
        branch_features = tree["feature"][branch_nodes]
        thresholds = tree["threshold"][branch_nodes]
        go_left = X[branch_idx, branch_features] <= thresholds
        left = tree["children_left"][branch_nodes]
        right = tree["children_right"][branch_nodes]
        node[branch_idx] = np.where(go_left, left, right)

    values = tree["value"][node]
    sums = values.sum(axis=1, keepdims=True)
    sums[sums == 0] = 1.0
    return values / sums


def predict_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["category", "confidence"])

    X = prepare_features(df)
    probs = np.zeros((X.shape[0], len(classes)), dtype=np.float64)
    for tree in _trees:
        probs += _tree_proba_batch(tree, X)
    probs /= max(len(_trees), 1)

    best = probs.argmax(axis=1)
    categories = classes[best]
    confidence = probs[np.arange(len(best)), best]

    result = pd.DataFrame(
        {"category": categories, "confidence": confidence}, index=df.index
    )
    for i, class_name in enumerate(classes):
        result[f"prob_{class_name}"] = probs[:, i]
    return result


def predict_flow(flow_data: dict) -> dict:
    result = predict_dataframe(pd.DataFrame([flow_data])).iloc[0]
    probability_map = {
        str(class_name): float(result[f"prob_{class_name}"])
        for class_name in classes
    }
    return {
        "category": str(result["category"]),
        "confidence": round(float(result["confidence"]), 4),
        "probabilities": probability_map,
    }


def top_model_features(limit: int = 5) -> list[dict]:
    if _importance_df.empty:
        return []
    rows = _importance_df.head(limit)
    return [
        {"name": str(row["Feature"]), "importance": float(row["Importance"])}
        for _, row in rows.iterrows()
    ]
