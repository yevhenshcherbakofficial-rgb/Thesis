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


def raw_ts(raw: dict) -> Optional[str]:
    return raw["data"].get("UtcTime")


class ReplayReader:
    def __init__(self, evtx_path: str, step_s: int = 5):
        self.path = Path(evtx_path)
        rows = [r for r in (normalize_record(raw, "live", "", "") for raw in parse_evtx(self.path)) if r]
        rows.sort(key=lambda r: r["ts"] or "")
        self.rows = rows
        self.t0 = pd.to_datetime(rows[0]["ts"], utc=True) if rows else None
        self.step = pd.Timedelta(seconds=step_s)
        self.clock = self.t0
        self.i = 0

    def new_events(self) -> List[dict]:
        if self.i >= len(self.rows):
            return []
        self.clock = self.clock + self.step
        out = []
        while self.i < len(self.rows) and pd.to_datetime(self.rows[self.i]["ts"], utc=True) <= self.clock:
            out.append(self.rows[self.i]); self.i += 1
        return out

    @property
    def active(self) -> bool:
        return self.i < len(self.rows)


class LivePollingReader:
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


class Pipeline:
    def __init__(self, config: dict):
        import joblib
        mdir = Path(config["paths"]["models"]) / config.get("_feature_set", "no_tree_context")
        import json
        bundle = joblib.load(mdir / "gbm.joblib")
        self.gbm = bundle["model"]
        self.feat_cols = bundle["feat_cols"]
        self.iforest = joblib.load(mdir / "iforest.joblib")
        self.fusion = config["models"]["fusion"]
        thr_path = mdir / "thresholds.json"
        self.thresholds = json.loads(thr_path.read_text()) if thr_path.exists() else {}
        self.alert_threshold = float(self.thresholds.get("fused", self.fusion["alert_threshold"]))
        self.window_s = int(config["models"]["feature_window_s"])
        self.seq_len = int(config["features"]["sequence_max_len"])
        self.autorun = config["features"]["autorun_registry_keys"]
        self.res_index: dict = {}
        self._explainer = None
        self.lstm, self.device = self._load_lstm(config, mdir)

    def _load_lstm(self, config, mdir):
        try:
            import torch
            from models import make_lstm
        except ImportError:
            return None, None
        path = mdir / "lstm.pt"
        if not path.exists():
            return None, None
        model = make_lstm(F.VOCAB_SIZE, config["models"]["lstm"])
        model.load_state_dict(torch.load(path, map_location="cpu"))
        model.eval()
        return model, "cpu"

    def load_resources(self, csv_path: Path) -> None:
        if csv_path.exists():
            r = pd.read_csv(csv_path)
            r["run_id"] = "live"
            r["ts_utc"] = pd.to_datetime(r["ts_utc"], utc=True, errors="coerce", format="ISO8601")
            r["start_utc"] = pd.to_datetime(r["start_utc"], utc=True, errors="coerce", format="ISO8601")
            self.res_index = F.resource_index(r.dropna(subset=["ts_utc", "start_utc"]))

    def score(self, buf: pd.DataFrame) -> pd.DataFrame:
        from models import fuse, iforest_scores, tree_aggregate
        buf = buf[buf["process_guid"].notna()]
        proc = F.process_table(buf)
        feats = F.window_features(buf, proc, self.window_s, self.autorun, self.res_index)
        if feats.empty:
            return feats
        X = feats[self.feat_cols].fillna(0).to_numpy(dtype=np.float32)
        gbm_p = self.gbm.predict_proba(X)[:, 1]
        anomaly = iforest_scores(self.iforest, X)

        lstm_p = np.zeros(len(feats))
        if self.lstm is not None:
            import torch
            ids, Xseq, _ = F.build_sequences(buf, self.seq_len, window_s=self.window_s)
            pos = {rg: i for i, rg in enumerate(ids)}
            rows = [pos.get((r, g)) for r, g in zip(feats["run_id"], feats["process_guid"])]
            have = [i for i, j in enumerate(rows) if j is not None]
            if have:
                sel = Xseq[[rows[i] for i in have]]
                with torch.no_grad():
                    probs = torch.sigmoid(self.lstm(torch.tensor(sel))).numpy()
                for k, i in enumerate(have):
                    lstm_p[i] = probs[k]

        final = tree_aggregate(feats, fuse(gbm_p, lstm_p, anomaly, self.fusion))
        feats = feats.copy()
        feats["gbm"], feats["lstm"], feats["anomaly"], feats["score"] = \
            gbm_p, lstm_p, anomaly, final
        return feats

    def top_features(self, feats_row: pd.Series, k: int = 5) -> List[str]:
        import shap
        if self._explainer is None:
            self._explainer = shap.TreeExplainer(self.gbm)
        x = feats_row[self.feat_cols].to_numpy(dtype=np.float32).reshape(1, -1)
        contrib = self._explainer.shap_values(x)[0]
        order = np.argsort(contrib)[::-1][:k]
        return [f"{self.feat_cols[i]}={feats_row[self.feat_cols[i]]:g} ({contrib[i]:+.2f})"
                for i in order if contrib[i] > 0]


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


def run(config: dict, reader, response_action: str, poll_s: int,
        alerts_out: Optional[str] = None) -> List[dict]:
    import json
    pipe = Pipeline(config)
    if isinstance(reader, ReplayReader):
        pipe.load_resources(reader.path.parent / "resources.csv")
    buf = pd.DataFrame(columns=SCHEMA)
    alerted: set = set()
    alert_thr = pipe.alert_threshold
    log: List[dict] = []

    print(f"[detect] started; response={response_action}; threshold={alert_thr:.4f}")
    while reader.active:
        rows = reader.new_events()
        if rows:
            new = pd.DataFrame(rows, columns=SCHEMA)
            new["ts"] = pd.to_datetime(new["ts"], utc=True, errors="coerce")
            new["label"] = 0
            buf = pd.concat([buf, new], ignore_index=True).dropna(subset=["ts"])
            buf["event_id"] = pd.to_numeric(buf["event_id"], errors="coerce")

            feats = pipe.score(buf)
            images = dict(zip(buf.loc[buf["event_id"] == 1, "process_guid"],
                              buf.loc[buf["event_id"] == 1, "image"]))
            now = reader.clock if isinstance(reader, ReplayReader) else pd.Timestamp.now(tz="UTC")
            final = not reader.active
            for _, r in feats.iterrows():
                if r["process_guid"] in alerted or r["score"] < alert_thr:
                    continue
                complete = ((now - r["start_ts"]).total_seconds() >= pipe.window_s
                            or r.get("terminated_in_window", 0) == 1 or final)
                if not complete:
                    continue
                alerted.add(r["process_guid"])
                a = Alert(r["process_guid"], F.basename(images.get(r["process_guid"], "")),
                          float(r["score"]), pipe.top_features(r),
                          event_chain(buf, r["process_guid"]))
                rec = {"process_guid": a.guid, "image": a.image, "score": round(a.score, 4),
                       "gbm": round(float(r["gbm"]), 4), "lstm": round(float(r["lstm"]), 4),
                       "anomaly": round(float(r["anomaly"]), 4),
                       "chain": a.chain, "top_features": a.top_features}
                if isinstance(reader, ReplayReader):
                    rec["replay_time_s"] = round((reader.clock - reader.t0).total_seconds(), 1)
                    rec["process_age_s"] = round((reader.clock - r["start_ts"]).total_seconds(), 1)
                log.append(rec)
                print(f"\n[ALERT] score={a.score:.3f} image={a.image} chain={' -> '.join(a.chain)}"
                      + (f" t+{rec['replay_time_s']}s" if "replay_time_s" in rec else ""))
                print(f"        features: {', '.join(a.top_features)}")
                respond(response_action, pid_of(buf, r["process_guid"]))

        if not isinstance(reader, ReplayReader):
            time.sleep(poll_s)
    if alerts_out:
        Path(alerts_out).write_text("\n".join(json.dumps(x) for x in log) + "\n", encoding="utf-8")
    print(f"[detect] stopped; {len(log)} alerts")
    return log


def main() -> None:
    ap = argparse.ArgumentParser(description="Real-time malicious process detection.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--replay", help="score an exported evtx instead of live")
    ap.add_argument("--response", default="notify",
                    choices=["notify", "suspend", "terminate"])
    ap.add_argument("--poll", type=int, default=5)
    ap.add_argument("--alerts-out", help="write alerts as JSON lines to this file")
    ap.add_argument("--feature-set", default="no_tree_context", help="trained model set to load")
    args = ap.parse_args()

    config = load_config(args.config)
    config["_feature_set"] = args.feature_set
    if args.replay:
        reader = ReplayReader(args.replay, step_s=args.poll)
    else:
        channel = "Microsoft-Windows-Sysmon/Operational"
        reader = LivePollingReader(channel, args.poll)
    run(config, reader, args.response, args.poll, args.alerts_out)


if __name__ == "__main__":
    main()
