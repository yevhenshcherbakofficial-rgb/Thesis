"""
features.py - Process tree, window features and event sequences.

    data/events.parquet  ->  data/features.parquet  +  data/sequences.pkl

For every process (identified by run_id + ProcessGuid) we build:
  * a fixed-length numeric feature vector aggregated over the first N seconds
    of the process's life (N = config.features.feature_window_s), covering the
    seven feature groups of Table 1.2 of the report;
  * an ordered sequence of event-type tokens for the LSTM model.

Resource-metric fields (CPU/RAM) are not present in Sysmon telemetry; here they
are approximated by activity proxies (event rate, image loads, child count).
Replace with ETW/perf-counter values if those are collected.

CLI:
    python features.py
"""
from __future__ import annotations

import argparse
import math
import os
import pickle
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

from collector import load_config

LOLBINS = {"powershell.exe", "cmd.exe", "rundll32.exe", "wmic.exe",
           "mshta.exe", "regsvr32.exe", "cscript.exe", "wscript.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
INTEGRITY_RANK = {"untrusted": 0, "low": 1, "medium": 2, "high": 3, "system": 4}

# Event-type -> token index for sequences (0 is reserved for padding).
EVENT_VOCAB = {1: 1, 3: 2, 7: 3, 8: 4, 10: 5, 11: 6, 13: 7}
VOCAB_SIZE = len(EVENT_VOCAB) + 1  # + padding


def shannon_entropy(s: str | None) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def basename(path: str | None) -> str:
    if not path:
        return ""
    return os.path.basename(path.replace("\\", "/")).lower()


# --------------------------------------------------------------------------- #
# Process tree
# --------------------------------------------------------------------------- #
def process_table(df: pd.DataFrame) -> pd.DataFrame:
    """One row per (run_id, process_guid): parent, depth, start_ts, metadata."""
    creates = df[df["event_id"] == 1].copy()
    # A process may legitimately appear once in ProcessCreate; keep the first.
    creates = creates.sort_values("ts").drop_duplicates(["run_id", "process_guid"])

    proc = creates[["run_id", "process_guid", "parent_guid", "ts",
                    "image", "command_line", "parent_image",
                    "integrity_level", "scenario", "kind"]].copy()
    proc = proc.rename(columns={"ts": "start_ts"})

    # Depth via parent chain, computed per run.
    depth_map: Dict[Tuple[str, str], int] = {}
    for run_id, grp in proc.groupby("run_id"):
        parent = dict(zip(grp["process_guid"], grp["parent_guid"]))

        def depth_of(guid: str) -> int:
            d, seen = 0, set()
            while guid in parent and parent[guid] and parent[guid] in parent:
                if guid in seen:            # guard against cycles
                    break
                seen.add(guid)
                guid = parent[guid]
                d += 1
            return d

        for g in grp["process_guid"]:
            depth_map[(run_id, g)] = depth_of(g)

    proc["depth"] = [depth_map[(r, g)] for r, g in
                     zip(proc["run_id"], proc["process_guid"])]
    return proc


def injected_guids(df: pd.DataFrame) -> set:
    """Processes that were the TARGET of a remote thread / process access."""
    inj = df[df["event_id"].isin([8, 10])]
    return set(zip(inj["run_id"], inj["target_guid"].fillna("")))


# --------------------------------------------------------------------------- #
# Window features
# --------------------------------------------------------------------------- #
def window_features(df: pd.DataFrame, proc: pd.DataFrame,
                    window_s: int, autorun_keys: List[str]) -> pd.DataFrame:
    inj = injected_guids(df)
    start_lookup = dict(zip(zip(proc["run_id"], proc["process_guid"]),
                            proc["start_ts"]))

    # Index events by process for fast per-group access.
    grouped = df.groupby(["run_id", "process_guid"], sort=False)
    rows = []
    for (run_id, guid), g in grouped:
        start = start_lookup.get((run_id, guid))
        if start is None or pd.isna(start):
            start = g["ts"].min()                       # no ProcessCreate seen
        window_end = start + pd.Timedelta(seconds=window_s)
        w = g[(g["ts"] >= start) & (g["ts"] <= window_end)]
        if w.empty:
            continue

        net = w[w["event_id"] == 3]
        reg = w[w["event_id"] == 13]
        autorun = 0
        if len(reg):
            keys = [k.lower().replace("\\", "/") for k in autorun_keys]
            autorun = int(reg["reg_target"].fillna("").apply(
                lambda t: any(k in t.lower().replace("\\", "/") for k in keys))
                .astype(int).sum())
        children = df[(df["run_id"] == run_id) & (df["event_id"] == 1) &
                      (df["parent_guid"] == guid) & (df["ts"] <= window_end)]

        duration = max((w["ts"].max() - start).total_seconds(), 1e-6)
        cmd = w["command_line"].dropna()
        cmd = cmd.iloc[0] if len(cmd) else ""
        img = basename(w["image"].dropna().iloc[0]) if w["image"].notna().any() else ""
        pimg = basename(w["parent_image"].dropna().iloc[0]) if w["parent_image"].notna().any() else ""
        integ = str(w["integrity_level"].dropna().iloc[0]).lower() if w["integrity_level"].notna().any() else ""

        rows.append({
            "run_id": run_id, "process_guid": guid,
            "start_ts": start,
            "label": int(w["label"].max()),
            "scenario": w["scenario"].iloc[0], "kind": w["kind"].iloc[0],
            # launch context / static
            "cmdline_len": len(cmd),
            "cmdline_entropy": shannon_entropy(cmd),
            "image_is_lolbin": int(img in LOLBINS),
            "parent_is_shell": int(pimg in SHELLS),
            "parent_is_office": int(pimg in OFFICE),
            "integrity_rank": INTEGRITY_RANK.get(integ, 2),
            "depth": int(proc_depth(proc, run_id, guid)),
            # activity / resource proxies
            "n_events": len(w),
            "event_rate": len(w) / duration,
            "n_img_load": int((w["event_id"] == 7).sum()),
            # file & registry
            "n_file_create": int((w["event_id"] == 11).sum()),
            "n_autorun_writes": int(autorun),
            "n_reg_set": len(reg),
            # network
            "n_net": len(net),
            "n_unique_ip": net["dest_ip"].nunique(),
            "n_unique_port": net["dest_port"].nunique(),
            # inter-process
            "n_children": len(children),
            "remote_thread_out": int((w["event_id"] == 8).sum()),
            "process_access_out": int((w["event_id"] == 10).sum()),
            "is_injected": int((run_id, guid) in inj),
        })
    return pd.DataFrame(rows)


def proc_depth(proc: pd.DataFrame, run_id: str, guid: str) -> int:
    hit = proc[(proc["run_id"] == run_id) & (proc["process_guid"] == guid)]
    return int(hit["depth"].iloc[0]) if len(hit) else 0


# --------------------------------------------------------------------------- #
# Sequences
# --------------------------------------------------------------------------- #
def build_sequences(df: pd.DataFrame, max_len: int, pad: str = "post"):
    """Return (ids, X, y): process ids, padded token matrix, labels."""
    ids, seqs, labels = [], [], []
    for (run_id, guid), g in df.sort_values("ts").groupby(
            ["run_id", "process_guid"], sort=False):
        toks = [EVENT_VOCAB.get(int(e), 0) for e in g["event_id"]]
        toks = [t for t in toks if t > 0]
        if not toks:
            continue
        if len(toks) > max_len:
            toks = toks[:max_len]
        ids.append((run_id, guid))
        seqs.append(toks)
        labels.append(int(g["label"].max()))

    X = np.zeros((len(seqs), max_len), dtype=np.int64)
    for i, toks in enumerate(seqs):
        if pad == "post":
            X[i, :len(toks)] = toks
        else:
            X[i, max_len - len(toks):] = toks
    return ids, X, np.asarray(labels, dtype=np.int64)


# --------------------------------------------------------------------------- #
def build_features(config: dict) -> None:
    df = pd.read_parquet(config["paths"]["events"])
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    proc = process_table(df)

    win = int(config["models"]["feature_window_s"])
    autorun_keys = config["features"]["autorun_registry_keys"]
    feats = window_features(df, proc, win, autorun_keys)

    out_f = Path(config["paths"]["features"])
    out_f.parent.mkdir(parents=True, exist_ok=True)
    feats.to_parquet(out_f, index=False)
    print(f"[done] {len(feats)} processes ({feats['label'].sum()} malicious) -> {out_f}")

    max_len = int(config["features"]["sequence_max_len"])
    ids, X, y = build_sequences(df, max_len, config["features"]["sequence_pad"])
    with open(config["paths"]["sequences"], "wb") as fh:
        pickle.dump({"ids": ids, "X": X, "y": y, "vocab_size": VOCAB_SIZE}, fh)
    print(f"[done] {len(ids)} sequences -> {config['paths']['sequences']}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Build features and sequences.")
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()
    build_features(load_config(args.config))


if __name__ == "__main__":
    main()
