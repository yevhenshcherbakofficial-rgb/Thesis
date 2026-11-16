"""
detect.py - Real-time detection prototype (report section 1.7).

Reads Sysmon telemetry, rebuilds process state incrementally, scores each
process with the trained two-stage pipeline, and raises explained alerts.

Readers:
  * live   - poll the Sysmon operational channel on Windows (wevtutil export).
  * replay - feed a previously exported .evtx (offline demo / testing).

Scoring reuses the exact feature code from features.py, so the online features
match the ones the models were trained on.

Response policy (config.models.fusion): default is notify (log only); suspend
and terminate are available for deployment but off by default.

CLI:
    python detect.py                       # live, notify only
    python detect.py --replay data/raw/<run_id>/sysmon.evtx
    python detect.py --response terminate  # enable active response
"""
from __future__ import annotations

import argparse
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

import features as F
from collector import SCHEMA, load_config, normalize_record, parse_evtx


# --------------------------------------------------------------------------- #
# Readers
# --------------------------------------------------------------------------- #
def raw_ts(raw: dict) -> Optional[str]:
    return raw["data"].get("UtcTime")


class ReplayReader:
    """Yield all events from an exported evtx once, in time order."""
    def __init__(self, evtx_path: str):
        self.path = Path(evtx_path)
        self._done = False

    def new_events(self) -> List[dict]:
        if self._done:
            return []
        self._done = True
        rows = []
        for raw in parse_evtx(self.path):
            row = normalize_record(raw, "live", "", "")
            if row:
                rows.append(row)
        return rows

    @property
    def active(self) -> bool:
        return not self._done


class LivePollingReader:
    """Poll the Sysmon channel by exporting it and emitting newly seen records."""
    def __init__(self, channel: str, interval_s: int = 5):
        self.channel = channel
        self.interval = interval_s
        self.last_ts = pd.Timestamp(0, tz="UTC")
        self.tmp = Path(tempfile.gettempdir()) / "detect_sysmon.evtx"

    def new_events(self) -> List[dict]:
        subprocess.run(["wevtutil", "epl", self.channel, str(self.tmp), "/ow:true"],
                       capture_output=True)
        rows = []
        for raw in parse_evtx(self.tmp):
            ts = pd.to_datetime(raw_ts(raw), utc=True, errors="coerce")
            if pd.isna(ts) or ts <= self.last_ts:
                continue
            row = normalize_record(raw, "live", "", "")
            if row:
                rows.append(row)
        if rows:
            self.last_ts = max(pd.to_datetime(r["ts"], utc=True) for r in rows)
        return rows

    @property
    def active(self) -> bool:
        return True


# --------------------------------------------------------------------------- #
# Model bundle
# --------------------------------------------------------------------------- #
class Pipeline:
    def __init__(self, config: dict):
        import joblib
        mdir = Path(config["paths"]["models"])
        bundle = joblib.load(mdir / "gbm.joblib")
        self.gbm = bundle["model"]
        self.feat_cols = bundle["feat_cols"]
        self.iforest = joblib.load(mdir / "iforest.joblib")
        self.fusion = config["models"]["fusion"]
        self.window_s = int(config["models"]["feature_window_s"])
        self.autorun = config["features"]["autorun_registry_keys"]
        self._importance = getattr(self.gbm, "feature_importances_", None)
        self.lstm, self.device = self._load_lstm(config, mdir)

    def _load_lstm(self, config, mdir):
        try:
            import torch
            from torch import nn
        except ImportError:
            return None, None
        p = config["models"]["lstm"]

        class LSTMClassifier(nn.Module):
            def __init__(self):
                super().__init__()
                self.emb = nn.Embedding(F.VOCAB_SIZE, p["embedding_dim"], padding_idx=0)
                self.lstm = nn.LSTM(p["embedding_dim"], p["hidden_dim"],
                                    num_layers=p["num_layers"], batch_first=True,
                                    dropout=p["dropout"] if p["num_layers"] > 1 else 0.0)
                self.head = nn.Sequential(nn.Dropout(p["dropout"]),
                                          nn.Linear(p["hidden_dim"], 1))

            def forward(self, x):
                lengths = (x != 0).sum(dim=1).clamp(min=1)
                out, _ = self.lstm(self.emb(x))
                idx = (lengths - 1).view(-1, 1, 1).expand(-1, 1, out.size(2))
                return self.head(out.gather(1, idx).squeeze(1)).squeeze(1)

        path = mdir / "lstm.pt"
        if not path.exists():
            return None, None
        model = LSTMClassifier()
        model.load_state_dict(torch.load(path, map_location="cpu"))
        model.eval()
        return model, "cpu"

    # -- scoring -----------------------------------------------------------
    def score(self, buf: pd.DataFrame) -> pd.DataFrame:
        """Score every process in the buffer; returns feats + score columns."""
        proc = F.process_table(buf)
        feats = F.window_features(buf, proc, self.window_s, self.autorun)
        if feats.empty:
            return feats
        X = feats[self.feat_cols].fillna(0).to_numpy(dtype=np.float32)
        gbm_p = self.gbm.predict_proba(X)[:, 1]
        anomaly = self._anomaly(X)

        lstm_p = np.zeros(len(feats))
        if self.lstm is not None:
            import torch
            ids, Xseq, _ = F.build_sequences(buf, 200)
            pos = {rg: i for i, rg in enumerate(ids)}
            rows = [pos.get((r, g)) for r, g in zip(feats["run_id"], feats["process_guid"])]
            have = [i for i, j in enumerate(rows) if j is not None]
            if have:
                sel = Xseq[[rows[i] for i in have]]
                with torch.no_grad():
                    probs = torch.sigmoid(self.lstm(torch.tensor(sel))).numpy()
                for k, i in enumerate(have):
                    lstm_p[i] = probs[k]

        suspect = gbm_p >= self.fusion["stage1_suspect_threshold"]
        final = gbm_p.copy()
        final[suspect] = np.maximum(gbm_p[suspect], lstm_p[suspect])
        final = np.clip(np.maximum(final, 0.3 * anomaly), 0, 1)

        feats = feats.copy()
        feats["gbm"], feats["lstm"], feats["anomaly"], feats["score"] = \
            gbm_p, lstm_p, anomaly, final
        return feats

    def _anomaly(self, X) -> np.ndarray:
        raw = -self.iforest.score_samples(X)
        lo, hi = raw.min(), raw.max()
        return (raw - lo) / (hi - lo + 1e-9)

    def top_features(self, feats_row: pd.Series, k: int = 5) -> List[str]:
        if self._importance is None:
            return []
        vals = feats_row[self.feat_cols].to_numpy(dtype=float)
        contrib = np.abs(vals) * self._importance
        order = np.argsort(contrib)[::-1][:k]
        return [f"{self.feat_cols[i]}={feats_row[self.feat_cols[i]]}" for i in order]


# --------------------------------------------------------------------------- #
# Alerts and response
# --------------------------------------------------------------------------- #
@dataclass
class Alert:
    guid: str
    image: str
    score: float
    top_features: List[str] = field(default_factory=list)
    chain: List[str] = field(default_factory=list)


def event_chain(buf: pd.DataFrame, guid: str) -> List[str]:
    creates = buf[buf["event_id"] == 1]
    parent = dict(zip(creates["process_guid"], creates["parent_guid"]))
    image = dict(zip(creates["process_guid"], creates["image"]))
    chain, seen = [], set()
    while guid and guid not in seen:
        seen.add(guid)
        chain.append(F.basename(image.get(guid, "")) or "?")
        guid = parent.get(guid)
    return list(reversed(chain))


def pid_of(buf: pd.DataFrame, guid: str) -> Optional[int]:
    row = buf[(buf["event_id"] == 1) & (buf["process_guid"] == guid)]
    if len(row) and pd.notna(row["pid"].iloc[0]):
        return int(row["pid"].iloc[0])
    return None


def respond(action: str, pid: Optional[int]) -> None:
    if action == "notify" or pid is None:
        return
    try:
        import psutil
        p = psutil.Process(pid)
        if action == "suspend":
            p.suspend()
        elif action == "terminate":
            p.terminate()
    except Exception:
        if action == "terminate":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)


# --------------------------------------------------------------------------- #
def run(config: dict, reader, response_action: str, poll_s: int) -> None:
    pipe = Pipeline(config)
    buf = pd.DataFrame(columns=SCHEMA)
    alerted: set = set()
    alert_thr = config["models"]["fusion"]["alert_threshold"]

    print(f"[detect] started; response={response_action}")
    while reader.active:
        rows = reader.new_events()
        if rows:
            new = pd.DataFrame(rows, columns=SCHEMA)
            new["ts"] = pd.to_datetime(new["ts"], utc=True, errors="coerce")
            new["label"] = 0
            buf = pd.concat([buf, new], ignore_index=True).dropna(subset=["ts"])

            feats = pipe.score(buf)
            for _, r in feats.iterrows():
                if r["process_guid"] in alerted or r["score"] < alert_thr:
                    continue
                alerted.add(r["process_guid"])
                a = Alert(r["process_guid"], F.basename(r.get("scenario") or ""),
                          float(r["score"]), pipe.top_features(r),
                          event_chain(buf, r["process_guid"]))
                print(f"\n[ALERT] score={a.score:.3f} chain={' -> '.join(a.chain)}")
                print(f"        features: {', '.join(a.top_features)}")
                respond(response_action, pid_of(buf, r["process_guid"]))

        if isinstance(reader, ReplayReader):
            break
        time.sleep(poll_s)
    print("[detect] stopped")


def main() -> None:
    ap = argparse.ArgumentParser(description="Real-time malicious process detection.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--replay", help="score an exported evtx instead of live")
    ap.add_argument("--response", default="notify",
                    choices=["notify", "suspend", "terminate"])
    ap.add_argument("--poll", type=int, default=5)
    args = ap.parse_args()

    config = load_config(args.config)
    if args.replay:
        reader = ReplayReader(args.replay)
    else:
        channel = "Microsoft-Windows-Sysmon/Operational"
        reader = LivePollingReader(channel, args.poll)
    run(config, reader, args.response, args.poll)


if __name__ == "__main__":
    main()
