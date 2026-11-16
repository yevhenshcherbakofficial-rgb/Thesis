"""
models.py - Training, evaluation and explanation.

Implements the two-stage detection scheme of report section 1.7:
  * Stage 1 - XGBoost on window features (fast triage of every process).
  * Stage 2 - LSTM on event sequences (deeper look at suspicious processes).
  * Isolation Forest - anomaly score, trained on benign processes only.
  * Decision fusion - combine scores and aggregate at process-tree level.

Evaluation uses a strictly time-based train/test split (TESSERACT, [15]) and
reports recall at a fixed low FPR, which is the operationally relevant metric.

    data/features.parquet + data/sequences.pkl  ->  data/models/*, data/reports/*

CLI:
    python models.py
"""
from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (average_precision_score, f1_score,
                             precision_score, recall_score, roc_auc_score,
                             roc_curve)

from collector import load_config

META_COLS = ["run_id", "process_guid", "start_ts", "label", "scenario", "kind"]


def feature_columns(feats: pd.DataFrame) -> List[str]:
    return [c for c in feats.columns if c not in META_COLS]


# --------------------------------------------------------------------------- #
# Data loading and temporal split
# --------------------------------------------------------------------------- #
def load_data(config: dict):
    feats = pd.read_parquet(config["paths"]["features"])
    feats["start_ts"] = pd.to_datetime(feats["start_ts"], utc=True)
    feats = feats.sort_values("start_ts").reset_index(drop=True)
    with open(config["paths"]["sequences"], "rb") as fh:
        seq = pickle.load(fh)
    return feats, seq


def temporal_split(feats: pd.DataFrame, q: float):
    """Train = earliest q share by time, test = the rest. No shuffling."""
    threshold = feats["start_ts"].quantile(q)
    train_mask = feats["start_ts"] <= threshold
    test_mask = ~train_mask
    return train_mask.to_numpy(), test_mask.to_numpy(), threshold


# --------------------------------------------------------------------------- #
# Stage 1 - gradient boosting
# --------------------------------------------------------------------------- #
def train_gbm(X_tr, y_tr, params: dict):
    from xgboost import XGBClassifier
    pos = max(int((y_tr == 1).sum()), 1)
    neg = int((y_tr == 0).sum())
    model = XGBClassifier(
        n_estimators=params["n_estimators"], max_depth=params["max_depth"],
        learning_rate=params["learning_rate"], subsample=params["subsample"],
        colsample_bytree=params["colsample_bytree"],
        scale_pos_weight=neg / pos, eval_metric="aucpr",
        tree_method="hist", n_jobs=-1,
    )
    model.fit(X_tr, y_tr)
    return model


# --------------------------------------------------------------------------- #
# Stage 2 - LSTM over event sequences
# --------------------------------------------------------------------------- #
def train_lstm(X_tr, y_tr, vocab_size: int, params: dict):
    import torch
    from torch import nn
    from torch.utils.data import DataLoader, TensorDataset

    torch.manual_seed(params.get("random_state", 42))
    device = "cuda" if torch.cuda.is_available() else "cpu"

    class LSTMClassifier(nn.Module):
        def __init__(self):
            super().__init__()
            self.emb = nn.Embedding(vocab_size, params["embedding_dim"],
                                    padding_idx=0)
            self.lstm = nn.LSTM(params["embedding_dim"], params["hidden_dim"],
                                num_layers=params["num_layers"], batch_first=True,
                                dropout=params["dropout"] if params["num_layers"] > 1 else 0.0)
            self.head = nn.Sequential(nn.Dropout(params["dropout"]),
                                      nn.Linear(params["hidden_dim"], 1))

        def forward(self, x):
            lengths = (x != 0).sum(dim=1).clamp(min=1)
            out, _ = self.lstm(self.emb(x))
            idx = (lengths - 1).view(-1, 1, 1).expand(-1, 1, out.size(2))
            last = out.gather(1, idx).squeeze(1)      # last real timestep
            return self.head(last).squeeze(1)

    model = LSTMClassifier().to(device)
    ds = TensorDataset(torch.tensor(X_tr), torch.tensor(y_tr, dtype=torch.float32))
    dl = DataLoader(ds, batch_size=params["batch_size"], shuffle=True)

    pos_weight = torch.tensor([max((y_tr == 0).sum(), 1) / max((y_tr == 1).sum(), 1)],
                              dtype=torch.float32, device=device)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    opt = torch.optim.Adam(model.parameters(), lr=params["lr"])

    model.train()
    for epoch in range(params["epochs"]):
        total = 0.0
        for xb, yb in dl:
            xb, yb = xb.to(device), yb.to(device)
            opt.zero_grad()
            loss = loss_fn(model(xb), yb)
            loss.backward()
            opt.step()
            total += loss.item() * len(xb)
        print(f"  [lstm] epoch {epoch + 1}/{params['epochs']} loss={total / len(ds):.4f}")
    return model, device


def lstm_predict(model, device, X) -> np.ndarray:
    import torch
    model.eval()
    with torch.no_grad():
        logits = model(torch.tensor(X).to(device))
        return torch.sigmoid(logits).cpu().numpy()


# --------------------------------------------------------------------------- #
# Anomaly detection
# --------------------------------------------------------------------------- #
def train_iforest(X_tr_benign, params: dict, random_state: int):
    model = IsolationForest(n_estimators=params["n_estimators"],
                            contamination=params["contamination"],
                            random_state=random_state, n_jobs=-1)
    model.fit(X_tr_benign)
    return model


def iforest_scores(model, X) -> np.ndarray:
    """Map IsolationForest.score_samples to [0,1], higher = more anomalous."""
    raw = -model.score_samples(X)          # higher = more anomalous
    lo, hi = raw.min(), raw.max()
    return (raw - lo) / (hi - lo + 1e-9)


# --------------------------------------------------------------------------- #
# Fusion and metrics
# --------------------------------------------------------------------------- #
def fuse(gbm_p: np.ndarray, lstm_p: np.ndarray, fusion: dict) -> np.ndarray:
    """Stage-2 score is used only for processes the stage-1 model found
    suspicious; others keep the stage-1 score."""
    suspect = gbm_p >= fusion["stage1_suspect_threshold"]
    final = gbm_p.copy()
    final[suspect] = np.maximum(gbm_p[suspect], lstm_p[suspect])
    return final


def tree_aggregate(feats: pd.DataFrame, scores: np.ndarray) -> np.ndarray:
    """Process-tree level decision (report section 1.7): each process's score is
    raised toward the strongest signal in its run, so an attack spread across a
    chain of individually quiet processes is still caught. The incident maximum
    bounds the per-run score; we blend it with the process's own score so a
    single hot process does not flatten the whole run to one value."""
    df = feats.copy()
    df["_score"] = scores
    run_max = df.groupby("run_id")["_score"].transform("max").to_numpy()
    return np.clip(np.maximum(scores, 0.5 * run_max + 0.5 * scores), 0, 1)


def recall_at_fpr(y_true, scores, target_fpr: float) -> Tuple[float, float]:
    fpr, tpr, thr = roc_curve(y_true, scores)
    ok = fpr <= target_fpr
    if not ok.any():
        return 0.0, float(thr[0])
    i = np.where(ok)[0][-1]
    return float(tpr[i]), float(thr[i])


def evaluate(y_true, scores, target_fpr: float, threshold: float) -> Dict[str, float]:
    pred = (scores >= threshold).astype(int)
    tn = int(((pred == 0) & (y_true == 0)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    rec_fpr, thr_fpr = recall_at_fpr(y_true, scores, target_fpr)
    return {
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, scores)) if len(set(y_true)) > 1 else float("nan"),
        "pr_auc": float(average_precision_score(y_true, scores)) if len(set(y_true)) > 1 else float("nan"),
        "fpr": fp / max(fp + tn, 1),
        f"recall_at_fpr_{target_fpr}": rec_fpr,
        "threshold_at_target_fpr": thr_fpr,
    }


# --------------------------------------------------------------------------- #
def shap_report(gbm, X_tr, feat_cols, out_dir: Path) -> None:
    try:
        import shap
    except ImportError:
        print("[warn] shap not installed; skipping explanations")
        return
    explainer = shap.TreeExplainer(gbm)
    sample = X_tr[:min(len(X_tr), 500)]
    vals = explainer.shap_values(sample)
    importance = np.abs(vals).mean(axis=0)
    ranking = sorted(zip(feat_cols, importance), key=lambda t: t[1], reverse=True)
    (out_dir / "shap_importance.json").write_text(
        json.dumps({k: float(v) for k, v in ranking}, indent=2))
    print("[shap] top features:", ", ".join(k for k, _ in ranking[:5]))


def align_sequences(feats: pd.DataFrame, seq: dict):
    """Return a sequence-row order aligned to the feats table (by run,guid)."""
    pos = {rg: i for i, rg in enumerate(seq["ids"])}
    order, mask = [], []
    for r, g in zip(feats["run_id"], feats["process_guid"]):
        j = pos.get((r, g))
        mask.append(j is not None)
        order.append(j if j is not None else 0)
    return np.asarray(order), np.asarray(mask)


def train(config: dict) -> dict:
    feats, seq = load_data(config)
    feat_cols = feature_columns(feats)
    X = feats[feat_cols].fillna(0).to_numpy(dtype=np.float32)
    y = feats["label"].to_numpy(dtype=np.int64)

    tr, te, thr_time = temporal_split(feats, config["models"]["split_time_quantile"])
    print(f"[split] train={tr.sum()} test={te.sum()} threshold={thr_time}")

    # Align sequences to the same rows/order as the feature table.
    order, has_seq = align_sequences(feats, seq)
    Xseq = seq["X"][order]

    mcfg = config["models"]
    # Stage 1
    gbm = train_gbm(X[tr], y[tr], mcfg["gbm"])
    gbm_p = gbm.predict_proba(X)[:, 1]
    # Stage 2
    lstm, device = train_lstm(Xseq[tr], y[tr], seq["vocab_size"],
                              {**mcfg["lstm"], "random_state": mcfg["random_state"]})
    lstm_p = lstm_predict(lstm, device, Xseq)
    lstm_p[~has_seq] = 0.0
    # Anomaly
    iforest = train_iforest(X[tr & (y == 0)], mcfg["isolation_forest"],
                            mcfg["random_state"])
    anomaly = iforest_scores(iforest, X)

    # Fusion + tree aggregation
    fused = fuse(gbm_p, lstm_p, mcfg["fusion"])
    fused = np.clip(np.maximum(fused, 0.3 * anomaly), 0, 1)
    fused = tree_aggregate(feats, fused)

    # Evaluate each stage on the held-out test set.
    target_fpr = mcfg["fusion"]["target_fpr"]
    thr = mcfg["fusion"]["alert_threshold"]
    report = {
        "n_train": int(tr.sum()), "n_test": int(te.sum()),
        "split_threshold": str(thr_time),
        "gbm": evaluate(y[te], gbm_p[te], target_fpr, thr),
        "lstm": evaluate(y[te], lstm_p[te], target_fpr, thr),
        "anomaly": evaluate(y[te], anomaly[te], target_fpr, thr),
        "fused": evaluate(y[te], fused[te], target_fpr, thr),
    }

    out_models = Path(config["paths"]["models"]); out_models.mkdir(parents=True, exist_ok=True)
    out_reports = Path(config["paths"]["reports"]); out_reports.mkdir(parents=True, exist_ok=True)

    import joblib
    joblib.dump({"model": gbm, "feat_cols": feat_cols}, out_models / "gbm.joblib")
    joblib.dump(iforest, out_models / "iforest.joblib")
    import torch
    torch.save(lstm.state_dict(), out_models / "lstm.pt")

    shap_report(gbm, X[tr], feat_cols, out_reports)
    (out_reports / "metrics.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Train and evaluate detectors.")
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()
    train(load_config(args.config))


if __name__ == "__main__":
    main()
