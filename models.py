from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (average_precision_score, f1_score,
                             precision_score, recall_score, roc_auc_score,
                             roc_curve)

from collector import load_config
from features import features_path

META_COLS = ["run_id", "process_guid", "parent_guid", "start_ts", "label",
             "scenario", "kind", "family", "split", "run_start", "holdout_family",
             "source", "alert"]


EXCLUDE: List[str] = []


def feature_columns(feats: pd.DataFrame) -> List[str]:
    return [c for c in feats.columns if c not in META_COLS and c not in EXCLUDE]


def load_runs(config: dict) -> pd.DataFrame:
    rows = []
    for mp in sorted(Path(config["paths"]["raw"]).glob("*/meta.json")):
        m = json.loads(mp.read_text(encoding="utf-8"))
        rows.append({"run_id": m["run_id"], "scenario": m.get("scenario"),
                     "kind": m.get("kind"), "run_label": m.get("label"),
                     "family": m.get("family"), "sha256": m.get("sha256"),
                     "seed_guid": m.get("seed_guid"),
                     "run_start": m.get("scenario_start_utc") or m.get("created_utc")})
    runs = pd.DataFrame(rows)
    runs["run_start"] = pd.to_datetime(runs["run_start"], utc=True, errors="coerce", format="ISO8601")
    return runs.sort_values("run_start").reset_index(drop=True)


def assign_splits(runs: pd.DataFrame, config: dict) -> pd.DataFrame:
    q = float(config["models"]["split_time_quantile"])
    vshare = float(config["models"].get("validation_share", 0.15))
    holdout = set(config["samples"].get("holdout_families") or [])
    runs = runs.copy()
    is_hold = runs["family"].isin(holdout)
    pool = runs[~is_hold].sort_values("run_start")
    n_train = int(round(len(pool) * q))
    train_ids = list(pool["run_id"].iloc[:n_train])
    n_val = max(int(round(len(train_ids) * vshare)), 1) if train_ids else 0
    val_ids = set(train_ids[len(train_ids) - n_val:])
    fit_ids = set(train_ids[:len(train_ids) - n_val])
    runs["split"] = "test"
    runs.loc[runs["run_id"].isin(fit_ids), "split"] = "train"
    runs.loc[runs["run_id"].isin(val_ids), "split"] = "val"
    runs["holdout_family"] = is_hold
    return runs


def attach(feats: pd.DataFrame, runs: pd.DataFrame) -> pd.DataFrame:
    cols = ["run_id", "split", "family", "run_start", "holdout_family"]
    f = feats.drop(columns=[c for c in cols if c != "run_id" and c in feats.columns])
    f = f.merge(runs[cols], on="run_id", how="inner")
    f["start_ts"] = pd.to_datetime(f["start_ts"], utc=True)
    return f.sort_values(["run_start", "start_ts"]).reset_index(drop=True)


def source_of(row_kind: str, holdout: bool) -> str:
    if row_kind == "sample" and holdout:
        return "sample_unseen_family"
    return {"simulator": "simulator", "atomic": "atomic", "sample": "sample",
            "workload": "benign_workload"}.get(row_kind, str(row_kind))


def train_gbm(X_tr, y_tr, params: dict, random_state: int = 42):
    from xgboost import XGBClassifier
    pos = max(int((y_tr == 1).sum()), 1)
    neg = int((y_tr == 0).sum())
    model = XGBClassifier(
        n_estimators=params["n_estimators"], max_depth=params["max_depth"],
        learning_rate=params["learning_rate"], subsample=params["subsample"],
        colsample_bytree=params["colsample_bytree"],
        scale_pos_weight=neg / pos, eval_metric="aucpr",
        tree_method="hist", n_jobs=-1, random_state=random_state,
    )
    model.fit(X_tr, y_tr)
    return model


def make_lstm(vocab_size: int, params: dict):
    from torch import nn

    class LSTMClassifier(nn.Module):
        def __init__(self):
            super().__init__()
            self.emb = nn.Embedding(vocab_size, params["embedding_dim"], padding_idx=0)
            self.lstm = nn.LSTM(params["embedding_dim"], params["hidden_dim"],
                                num_layers=params["num_layers"], batch_first=True,
                                dropout=params["dropout"] if params["num_layers"] > 1 else 0.0)
            self.head = nn.Sequential(nn.Dropout(params["dropout"]),
                                      nn.Linear(params["hidden_dim"], 1))

        def forward(self, x):
            lengths = (x != 0).sum(dim=1).clamp(min=1)
            out, _ = self.lstm(self.emb(x))
            idx = (lengths - 1).view(-1, 1, 1).expand(-1, 1, out.size(2))
            last = out.gather(1, idx).squeeze(1)
            return self.head(last).squeeze(1)

    return LSTMClassifier()


def train_lstm(X_tr, y_tr, vocab_size: int, params: dict):
    import torch
    from torch import nn
    from torch.utils.data import DataLoader, TensorDataset

    torch.manual_seed(params.get("random_state", 42))
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = make_lstm(vocab_size, params).to(device)
    ds = TensorDataset(torch.tensor(X_tr), torch.tensor(y_tr, dtype=torch.float32))
    dl = DataLoader(ds, batch_size=params["batch_size"], shuffle=True,
                    generator=torch.Generator().manual_seed(params.get("random_state", 42)))
    pos_weight = torch.tensor([max((y_tr == 0).sum(), 1) / max((y_tr == 1).sum(), 1)],
                              dtype=torch.float32, device=device)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    opt = torch.optim.Adam(model.parameters(), lr=params["lr"])
    history = []
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
        history.append(total / len(ds))
        print(f"  [lstm] epoch {epoch + 1}/{params['epochs']} loss={history[-1]:.4f}")
    return model, device, history


def lstm_predict(model, device, X, batch: int = 4096) -> np.ndarray:
    import torch
    model.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(X), batch):
            out.append(torch.sigmoid(model(torch.tensor(X[i:i + batch]).to(device))).cpu().numpy())
    return np.concatenate(out) if out else np.zeros(0)


def train_iforest(X_tr_benign, params: dict, random_state: int) -> dict:
    model = IsolationForest(n_estimators=params["n_estimators"],
                            contamination=params["contamination"],
                            random_state=random_state, n_jobs=-1)
    model.fit(X_tr_benign)
    raw = -model.score_samples(X_tr_benign)
    return {"model": model, "lo": float(np.quantile(raw, 0.01)), "hi": float(np.quantile(raw, 0.999))}


def iforest_scores(bundle: dict, X) -> np.ndarray:
    raw = -bundle["model"].score_samples(X)
    return np.clip((raw - bundle["lo"]) / (bundle["hi"] - bundle["lo"] + 1e-9), 0, 1)


def fuse(gbm_p: np.ndarray, lstm_p: np.ndarray, anomaly: np.ndarray, fusion: dict) -> np.ndarray:
    suspect = gbm_p >= fusion["stage1_suspect_threshold"]
    final = gbm_p.copy()
    final[suspect] = np.maximum(gbm_p[suspect], lstm_p[suspect])
    return np.clip(np.maximum(final, fusion.get("anomaly_weight", 0.3) * anomaly), 0, 1)


def tree_aggregate(feats: pd.DataFrame, scores: np.ndarray) -> np.ndarray:
    out = scores.copy()
    for run_id, idx in feats.groupby("run_id").indices.items():
        guids = feats["process_guid"].to_numpy()[idx]
        parents = feats["parent_guid"].to_numpy()[idx]
        own = dict(zip(guids, scores[idx]))
        parent = dict(zip(guids, parents))
        for k, g in zip(idx, guids):
            best, p, seen = 0.0, parent.get(g), set()
            while p in own and p not in seen:
                seen.add(p)
                best = max(best, own[p])
                p = parent.get(p)
            out[k] = max(scores[k], 0.5 * scores[k] + 0.5 * best)
    return np.clip(out, 0, 1)


def threshold_at_fpr(y, s, target_fpr: float) -> float:
    neg = np.sort(s[y == 0])[::-1]
    if len(neg) == 0:
        return 0.5
    k = int(np.floor(target_fpr * len(neg)))
    return float(np.nextafter(neg[k], 1.0)) if k < len(neg) else float(neg[-1])


def recall_at_fpr(y_true, scores, target_fpr: float) -> float:
    if len(set(y_true)) < 2:
        return float("nan")
    fpr, tpr, _ = roc_curve(y_true, scores)
    ok = fpr <= target_fpr
    return float(tpr[np.where(ok)[0][-1]]) if ok.any() else 0.0


def evaluate(y, s, thr: float, target_fpr: float) -> Dict[str, float]:
    pred = (s >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    two = len(set(y)) > 1
    return {
        "n": int(len(y)), "n_pos": int(y.sum()), "n_neg": int((y == 0).sum()),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "threshold": float(thr),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "fpr": fp / max(fp + tn, 1),
        "roc_auc": float(roc_auc_score(y, s)) if two else float("nan"),
        "pr_auc": float(average_precision_score(y, s)) if two else float("nan"),
        "recall_at_target_fpr": recall_at_fpr(y, s, target_fpr),
    }


def shap_values(gbm, X, feat_cols, out_dir: Path, n: int = 2000, seed: int = 42) -> pd.DataFrame:
    import shap
    rng = np.random.default_rng(seed)
    idx = rng.choice(len(X), size=min(n, len(X)), replace=False)
    sample = X[idx]
    vals = shap.TreeExplainer(gbm).shap_values(sample)
    np.savez_compressed(out_dir / "shap_values.npz", values=vals, X=sample,
                        features=np.array(feat_cols))
    imp = pd.DataFrame({"feature": feat_cols, "mean_abs_shap": np.abs(vals).mean(axis=0)})
    imp = imp.sort_values("mean_abs_shap", ascending=False)
    imp.to_csv(out_dir / "shap_importance.csv", index=False)
    print("[shap] top features:", ", ".join(imp["feature"].head(5)))
    return imp


def align_sequences(feats: pd.DataFrame, seq: dict):
    pos = {rg: i for i, rg in enumerate(seq["ids"])}
    order, mask = [], []
    for r, g in zip(feats["run_id"], feats["process_guid"]):
        j = pos.get((r, g))
        mask.append(j is not None)
        order.append(j if j is not None else 0)
    return np.asarray(order), np.asarray(mask)


def time_to_detection(config: dict, runs: pd.DataFrame, feats30: pd.DataFrame,
                      thr30: float, gbm30, cols30, random_state: int) -> pd.DataFrame:
    mcfg = config["models"]
    target_fpr = mcfg["fusion"]["target_fpr"]
    windows = sorted(int(w) for w in config["features"]["windows_s"])
    per_window = {}
    for w in windows:
        if w == int(mcfg["feature_window_s"]):
            f = feats30
            gbm, cols, thr = gbm30, cols30, thr30
        else:
            f = attach(pd.read_parquet(features_path(config, w)), runs)
            cols = feature_columns(f)
            X = f[cols].fillna(0).to_numpy(dtype=np.float32)
            y = f["label"].to_numpy(dtype=np.int64)
            tr, va = (f["split"] == "train").to_numpy(), (f["split"] == "val").to_numpy()
            gbm = train_gbm(X[tr], y[tr], mcfg["gbm"], random_state)
            thr = threshold_at_fpr(y[va], gbm.predict_proba(X[va])[:, 1], target_fpr)
        X = f[cols].fillna(0).to_numpy(dtype=np.float32)
        f = f.assign(alert=(gbm.predict_proba(X)[:, 1] >= thr).astype(int))
        per_window[w] = f[(f["split"] == "test") & (f["label"] == 1)]
    rows = []
    starts = dict(zip(runs["run_id"], runs["run_start"]))
    test_mal = runs[(runs["split"] == "test") & (runs["run_label"] == "malicious")]
    for _, r in test_mal.iterrows():
        best = None
        for w in windows:
            hits = per_window[w][(per_window[w]["run_id"] == r["run_id"]) & (per_window[w]["alert"] == 1)]
            if len(hits):
                off = (hits["start_ts"] - starts[r["run_id"]]).dt.total_seconds().clip(lower=0)
                t = float((off + w).min())
                best = t if best is None else min(best, t)
        rows.append({"run_id": r["run_id"], "scenario": r["scenario"], "kind": r["kind"],
                     "family": r["family"], "holdout_family": bool(r["holdout_family"]),
                     "detected": best is not None, "ttd_s": best})
    return pd.DataFrame(rows)


def train(config: dict) -> dict:
    mcfg = config["models"]
    rs = int(mcfg["random_state"])
    target_fpr = float(mcfg["fusion"]["target_fpr"])
    runs = assign_splits(load_runs(config), config)
    feats = attach(pd.read_parquet(config["paths"]["features"]), runs)
    with open(config["paths"]["sequences"], "rb") as fh:
        seq = pickle.load(fh)

    feat_cols = feature_columns(feats)
    X = feats[feat_cols].fillna(0).to_numpy(dtype=np.float32)
    y = feats["label"].to_numpy(dtype=np.int64)
    split = feats["split"].to_numpy()
    tr, va, te = split == "train", split == "val", split == "test"
    print(f"[split] runs train={int((runs.split == 'train').sum())} val={int((runs.split == 'val').sum())} "
          f"test={int((runs.split == 'test').sum())} | processes train={tr.sum()} val={va.sum()} "
          f"test={te.sum()} | malicious train={y[tr].sum()} val={y[va].sum()} test={y[te].sum()}")

    order, has_seq = align_sequences(feats, seq)
    Xseq = seq["X"][order]

    gbm = train_gbm(X[tr], y[tr], mcfg["gbm"], rs)
    gbm_p = gbm.predict_proba(X)[:, 1]
    lstm, device, lstm_hist = train_lstm(Xseq[tr], y[tr], seq["vocab_size"],
                                         {**mcfg["lstm"], "random_state": rs})
    lstm_p = lstm_predict(lstm, device, Xseq)
    lstm_p[~has_seq] = 0.0
    iforest = train_iforest(X[tr & (y == 0)], mcfg["isolation_forest"], rs)
    anomaly = iforest_scores(iforest, X)
    fused_raw = fuse(gbm_p, lstm_p, anomaly, mcfg["fusion"])
    fused = tree_aggregate(feats, fused_raw)

    stages = {"gbm": gbm_p, "lstm": lstm_p, "anomaly": anomaly,
              "fused_no_tree": fused_raw, "fused": fused}
    thresholds = {k: threshold_at_fpr(y[va], s[va], target_fpr) for k, s in stages.items()}

    feats["source"] = [source_of(k, h) for k, h in zip(feats["kind"], feats["holdout_family"])]
    report: dict = {
        "target_fpr": target_fpr,
        "runs": {s: int((runs.split == s).sum()) for s in ("train", "val", "test")},
        "processes": {"train": int(tr.sum()), "val": int(va.sum()), "test": int(te.sum())},
        "thresholds_from_validation": thresholds,
        "overall_test": {k: evaluate(y[te], s[te], thresholds[k], target_fpr) for k, s in stages.items()},
        "overall_val": {k: evaluate(y[va], s[va], thresholds[k], target_fpr) for k, s in stages.items()},
        "lstm_train_loss": lstm_hist,
    }

    neg_te = te & (y == 0)
    def group_eval(mask_pos):
        m = neg_te | (te & mask_pos & (y == 1))
        return {k: evaluate(y[m], s[m], thresholds[k], target_fpr) for k, s in stages.items()}
    report["by_source_test"] = {src: group_eval((feats["source"] == src).to_numpy())
                                for src in sorted(feats.loc[te & (y == 1), "source"].unique())}
    report["by_scenario_test"] = {sc: group_eval((feats["scenario"] == sc).to_numpy())
                                  for sc in sorted(feats.loc[te & (y == 1), "scenario"].unique())}
    fam_mask = feats["family"].notna().to_numpy()
    report["by_family_test"] = {fam: group_eval((feats["family"] == fam).to_numpy())
                                for fam in sorted(feats.loc[te & (y == 1) & fam_mask, "family"].unique())}

    alert = fused >= thresholds["fused"]
    feats["alert"] = alert
    run_rows = []
    for run_id, g in feats[te].groupby("run_id"):
        mal = g[g["label"] == 1]
        run_rows.append({"run_id": run_id, "scenario": g["scenario"].iloc[0], "kind": g["kind"].iloc[0],
                         "family": g["family"].iloc[0], "source": g["source"].iloc[0],
                         "n_processes": len(g), "n_malicious": len(mal),
                         "detected": bool(mal["alert"].any()) if len(mal) else None,
                         "false_alerts": int((g["alert"] & (g["label"] == 0)).sum())})
    run_df = pd.DataFrame(run_rows)

    out_models = Path(config["paths"]["models"]) / config["_feature_set"]
    out_reports = Path(config["paths"]["reports"]) / config["_feature_set"]
    out_models.mkdir(parents=True, exist_ok=True); out_reports.mkdir(parents=True, exist_ok=True)
    report["feature_set"] = config["_feature_set"]
    report["excluded_features"] = list(EXCLUDE)
    report["n_features"] = len(feat_cols)
    run_df.to_csv(out_reports / "runs_test.csv", index=False)

    ttd = time_to_detection(config, runs, feats, thresholds["gbm"], gbm, feat_cols, rs)
    ttd.to_csv(out_reports / "time_to_detection.csv", index=False)
    report["time_to_detection"] = {
        "malicious_test_runs": int(len(ttd)),
        "detected": int(ttd["detected"].sum()),
        "median_s": float(ttd["ttd_s"].median()) if ttd["detected"].any() else None,
        "within_10s": float((ttd["ttd_s"] <= 10).mean()) if len(ttd) else None,
        "within_30s": float((ttd["ttd_s"] <= 30).mean()) if len(ttd) else None,
    }

    import joblib
    import torch
    joblib.dump({"model": gbm, "feat_cols": feat_cols}, out_models / "gbm.joblib")
    joblib.dump(iforest, out_models / "iforest.joblib")
    torch.save(lstm.state_dict(), out_models / "lstm.pt")
    (out_models / "thresholds.json").write_text(json.dumps(thresholds, indent=2))

    shap_values(gbm, X[te], feat_cols, out_reports)
    pred = feats[["run_id", "process_guid", "parent_guid", "start_ts", "split", "label",
                  "scenario", "kind", "family", "source", "holdout_family"]].copy()
    for k, s in stages.items():
        pred[k] = s
    pred.to_parquet(out_reports / "predictions.parquet", index=False)
    runs.to_csv(out_reports / "runs_split.csv", index=False)
    (out_reports / "metrics.json").write_text(json.dumps(report, indent=2, default=str))
    o = report["overall_test"]["fused"]
    print(f"[test fused] P={o['precision']:.3f} R={o['recall']:.3f} F1={o['f1']:.3f} "
          f"FPR={o['fpr']:.4f} ROC-AUC={o['roc_auc']:.3f} R@FPR={o['recall_at_target_fpr']:.3f}")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Train and evaluate detectors.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--feature-set", default="full",
                    help="name from config.models.feature_sets (features to exclude)")
    args = ap.parse_args()
    cfg = load_config(args.config)
    sets = cfg["models"].get("feature_sets", {"full": []})
    EXCLUDE[:] = list(sets[args.feature_set] or [])
    cfg["_feature_set"] = args.feature_set
    print(f"[features] set={args.feature_set} excluded={EXCLUDE}")
    train(cfg)


if __name__ == "__main__":
    main()
