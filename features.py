from __future__ import annotations

import argparse
import math
import os
import pickle
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

from collector import load_config

LOLBINS = {"powershell.exe", "cmd.exe", "rundll32.exe", "wmic.exe", "mshta.exe",
           "regsvr32.exe", "cscript.exe", "wscript.exe", "certutil.exe",
           "bitsadmin.exe", "schtasks.exe", "msbuild.exe", "installutil.exe",
           "regasm.exe", "regsvcs.exe", "msiexec.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
INTEGRITY_RANK = {"untrusted": 0, "low": 1, "medium": 2, "high": 3, "system": 4}
EXEC_EXT = (".exe", ".dll", ".scr", ".ps1", ".bat", ".vbs", ".js", ".cmd")
HIGH_ACCESS_MASK = 0x0020 | 0x0008 | 0x0002 | 0x1F0FFF

EVENT_VOCAB = {1: 1, 3: 2, 7: 3, 8: 4, 10: 5, 11: 6, 13: 7, 12: 8, 22: 9, 23: 10, 26: 10, 5: 11}
VOCAB_SIZE = max(EVENT_VOCAB.values()) + 1


def shannon_entropy(s: str | None) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def basename(path: str | None) -> str:
    if not path or (isinstance(path, float) and math.isnan(path)):
        return ""
    return os.path.basename(str(path).replace("\\", "/")).lower()


def _first(series: pd.Series):
    s = series.dropna()
    return s.iloc[0] if len(s) else None


def _hex(v) -> int:
    try:
        return int(str(v), 16)
    except (TypeError, ValueError):
        return 0


def process_table(df: pd.DataFrame) -> pd.DataFrame:
    creates = df[df["event_id"] == 1].copy()
    creates = creates.sort_values("ts").drop_duplicates(["run_id", "process_guid"])

    proc = creates[["run_id", "process_guid", "parent_guid", "ts", "pid",
                    "image", "command_line", "parent_image",
                    "integrity_level", "scenario", "kind"]].copy()
    proc = proc.rename(columns={"ts": "start_ts"})

    depth_map: Dict[Tuple[str, str], int] = {}
    for run_id, grp in proc.groupby("run_id"):
        parent = dict(zip(grp["process_guid"], grp["parent_guid"]))
        memo: Dict[str, int] = {}

        def depth_of(guid: str) -> int:
            chain, seen = [], set()
            while guid in parent and parent[guid] in parent and guid not in seen:
                if guid in memo:
                    break
                seen.add(guid)
                chain.append(guid)
                guid = parent[guid]
            d = memo.get(guid, 0)
            for g in reversed(chain):
                d += 1
                memo[g] = d
            return memo.get(chain[0], d) if chain else d

        for g in grp["process_guid"]:
            depth_map[(run_id, g)] = depth_of(g)

    proc["depth"] = [depth_map[(r, g)] for r, g in zip(proc["run_id"], proc["process_guid"])]
    return proc


def injected_guids(df: pd.DataFrame) -> set:
    inj = df[df["event_id"] == 8]
    return set(zip(inj["run_id"], inj["target_guid"].fillna("")))


RES_COLS = ["res_samples", "cpu_max_pct", "cpu_mean_pct", "cpu_total_s",
            "ws_max_mb", "ws_growth_mb", "private_max_mb",
            "threads_max", "threads_growth", "handles_max"]


def load_resources(config: dict) -> pd.DataFrame:
    frames = []
    for csv_path in sorted(Path(config["paths"]["raw"]).glob("*/resources.csv")):
        try:
            r = pd.read_csv(csv_path)
        except Exception:
            continue
        r["run_id"] = csv_path.parent.name
        frames.append(r)
    if not frames:
        return pd.DataFrame()
    res = pd.concat(frames, ignore_index=True)
    res["ts_utc"] = pd.to_datetime(res["ts_utc"], utc=True, errors="coerce", format="ISO8601")
    res["start_utc"] = pd.to_datetime(res["start_utc"], utc=True, errors="coerce", format="ISO8601")
    return res.dropna(subset=["ts_utc", "start_utc"])


def resource_index(res: pd.DataFrame) -> Dict[Tuple[str, int], pd.DataFrame]:
    if res is None or res.empty:
        return {}
    return {(r, int(p)): g.sort_values("ts_utc") for (r, p), g in res.groupby(["run_id", "pid"])}


def resource_features(rows: pd.DataFrame | None, start, window_end) -> Dict[str, float]:
    out = dict.fromkeys(RES_COLS, 0.0)
    if rows is None or rows.empty:
        return out
    rows = rows[(rows["start_utc"] - start).abs() <= pd.Timedelta(seconds=2)]
    rows = rows[rows["ts_utc"] <= window_end]
    if rows.empty:
        return out
    t = rows["ts_utc"].astype("int64").to_numpy() / 1e9
    cpu = rows["cpu_s"].to_numpy(dtype=float)
    pct = np.diff(cpu) / np.maximum(np.diff(t), 1e-3) * 100 if len(rows) > 1 else np.array([0.0])
    ws = rows["ws_mb"].to_numpy(dtype=float)
    th = rows["threads"].to_numpy(dtype=float)
    out.update(res_samples=float(len(rows)), cpu_max_pct=float(np.max(pct)),
               cpu_mean_pct=float(np.mean(pct)), cpu_total_s=float(cpu[-1]),
               ws_max_mb=float(ws.max()), ws_growth_mb=float(ws.max() - ws[0]),
               private_max_mb=float(rows["private_mb"].max()),
               threads_max=float(th.max()), threads_growth=float(th.max() - th[0]),
               handles_max=float(rows["handles"].max()))
    return out


def window_features(df: pd.DataFrame, proc: pd.DataFrame,
                    window_s: int, autorun_keys: List[str],
                    res_index: Dict[Tuple[str, int], pd.DataFrame] | None = None,
                    include_preexisting: bool = False) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()
    res_index = res_index or {}
    inj = injected_guids(df)
    pinfo = {(r, g): row for r, g, row in zip(proc["run_id"], proc["process_guid"],
                                               proc.to_dict("records"))}
    keys = [k.lower().replace("\\", "/") for k in autorun_keys]

    child_ts: Dict[Tuple[str, str], List] = defaultdict(list)
    for r, pg, t in zip(proc["run_id"], proc["parent_guid"], proc["start_ts"]):
        child_ts[(r, pg)].append(t)

    rows = []
    for (run_id, guid), g in df.groupby(["run_id", "process_guid"], sort=False):
        if not guid or guid != guid:
            continue
        p = pinfo.get((run_id, guid))
        if p is None and not include_preexisting:
            continue
        start = p["start_ts"] if p is not None else g["ts"].min()
        if start is None or pd.isna(start):
            start = g["ts"].min()
        window_end = start + pd.Timedelta(seconds=window_s)
        w = g[(g["ts"] >= start) & (g["ts"] <= window_end)]
        if w.empty:
            continue
        eid = w["event_id"].to_numpy()

        net = w[eid == 3]
        reg = w[eid == 13]
        files = w[eid == 11]
        dns = w[eid == 22]
        loads = w[eid == 7]
        access = w[eid == 10]
        autorun = 0
        if len(reg):
            autorun = int(reg["reg_target"].fillna("").map(
                lambda t: any(k in t.lower().replace("\\", "/") for k in keys)).sum())
        n_children = sum(1 for t in child_ts.get((run_id, guid), []) if t <= window_end)

        cmd = (p.get("command_line") if p is not None else None) or _first(w["command_line"]) or ""
        img = basename((p.get("image") if p is not None else None) or _first(w["image"]))
        pimg = basename((p.get("parent_image") if p is not None else None) or _first(w["parent_image"]))
        integ = str((p.get("integrity_level") if p is not None else None)
                    or _first(w["integrity_level"]) or "").lower()
        duration = max((w["ts"].max() - start).total_seconds(), 1e-6)
        terminated = (eid == 5).any()
        lbl = pd.to_numeric(w["label"], errors="coerce").max() if "label" in w else 0
        acc_masks = access["granted_access"].map(_hex) if len(access) else pd.Series(dtype=int)
        acc_targets = access["target_guid"].fillna("") if len(access) else pd.Series(dtype=str)

        rows.append({
            "run_id": run_id, "process_guid": guid,
            "parent_guid": p.get("parent_guid") if p is not None else None,
            "start_ts": start,
            "label": int(lbl) if lbl == lbl and lbl is not None else 0,
            "scenario": _first(w["scenario"]), "kind": _first(w["kind"]),
            "cmdline_len": len(cmd),
            "cmdline_entropy": shannon_entropy(cmd),
            "cmdline_n_args": len(cmd.split()),
            "image_is_lolbin": int(img in LOLBINS),
            "image_is_shell": int(img in SHELLS),
            "parent_is_shell": int(pimg in SHELLS),
            "parent_is_office": int(pimg in OFFICE),
            "parent_is_lolbin": int(pimg in LOLBINS),
            "integrity_rank": INTEGRITY_RANK.get(integ, 2),
            "depth": int(p["depth"]) if p is not None else 0,
            "n_events": len(w),
            "event_rate": len(w) / duration,
            "n_img_load": len(loads),
            "n_unsigned_load": int((loads["signed"].fillna("").str.lower() == "false").sum()),
            "terminated_in_window": int(terminated),
            "lifetime_in_window_s": duration if terminated else float(window_s),
            "n_file_create": len(files),
            "n_exec_file_create": int(files["target_filename"].fillna("").str.lower()
                                      .str.endswith(EXEC_EXT).sum()),
            "n_unique_file_ext": files["target_filename"].fillna("").map(
                lambda f: os.path.splitext(f)[1].lower()).nunique(),
            "n_file_delete": int(np.isin(eid, (23, 26)).sum()),
            "n_autorun_writes": int(autorun),
            "n_reg_set": len(reg),
            "n_reg_key_op": int((eid == 12).sum()),
            "n_net": len(net),
            "n_unique_ip": net["dest_ip"].nunique(),
            "n_unique_port": net["dest_port"].nunique(),
            "n_dns": len(dns),
            "n_unique_domain": dns["dns_query"].nunique(),
            "n_children": n_children,
            "remote_thread_out": int((eid == 8).sum()),
            "process_access_out": len(access),
            "n_high_access_out": int((acc_masks & HIGH_ACCESS_MASK).astype(bool).sum()) if len(access) else 0,
            "n_access_targets": acc_targets.nunique() if len(access) else 0,
            "lsass_access": int(access["target_filename"].fillna("").str.lower()
                                .str.endswith("lsass.exe").sum()) if len(access) else 0,
            "is_injected": int((run_id, guid) in inj),
            **resource_features(
                res_index.get((run_id, int(p["pid"])))
                if p is not None and p.get("pid") == p.get("pid") and p.get("pid") is not None else None,
                start, window_end),
        })
    return pd.DataFrame(rows)


def build_sequences(df: pd.DataFrame, max_len: int, pad: str = "post", window_s: int | None = None):
    ids, seqs, labels = [], [], []
    for (run_id, guid), g in df.sort_values("ts").groupby(["run_id", "process_guid"], sort=False):
        if window_s is not None and len(g):
            g = g[g["ts"] <= g["ts"].iloc[0] + pd.Timedelta(seconds=window_s)]
        toks = [EVENT_VOCAB.get(int(e), 0) for e in g["event_id"]]
        toks = [t for t in toks if t > 0]
        if not toks:
            continue
        toks = toks[:max_len]
        ids.append((run_id, guid))
        seqs.append(toks)
        lbl = pd.to_numeric(g["label"], errors="coerce").max() if "label" in g else 0
        labels.append(int(lbl) if lbl == lbl and lbl is not None else 0)

    X = np.zeros((len(seqs), max_len), dtype=np.int64)
    for i, toks in enumerate(seqs):
        if pad == "post":
            X[i, :len(toks)] = toks
        else:
            X[i, max_len - len(toks):] = toks
    return ids, X, np.asarray(labels, dtype=np.int64)


def features_path(config: dict, window_s: int) -> Path:
    base = Path(config["paths"]["features"])
    if int(window_s) == int(config["models"]["feature_window_s"]):
        return base
    return base.with_name(f"{base.stem}_w{int(window_s)}{base.suffix}")


def staging_launchers(config: dict) -> set:
    import json
    out = set()
    for mp in Path(config["paths"]["raw"]).glob("*/meta.json"):
        m = json.loads(mp.read_text(encoding="utf-8"))
        if m.get("kind") in ("sample", "atomic") and m.get("seed_guid"):
            out.add((m["run_id"], m["seed_guid"]))
    return out


def build_features(config: dict) -> None:
    df = pd.read_parquet(config["paths"]["events"])
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce").astype("Int64")
    df = df[df["process_guid"].notna()]
    proc = process_table(df)
    res_idx = resource_index(load_resources(config))
    print(f"[res] resource series for {len(res_idx)} (run, pid) pairs")

    autorun_keys = config["features"]["autorun_registry_keys"]
    windows = sorted({int(w) for w in config["features"]["windows_s"]}
                     | {int(config["models"]["feature_window_s"])})
    launchers = staging_launchers(config)
    for win in windows:
        feats = window_features(df, proc, win, autorun_keys, res_idx)
        n0 = len(feats)
        feats = feats[~pd.Series(list(zip(feats["run_id"], feats["process_guid"]))).isin(launchers).to_numpy()]
        print(f"[drop] window {win}s: {n0 - len(feats)} staging launcher processes (sample/atomic runs)")
        out_f = features_path(config, win)
        out_f.parent.mkdir(parents=True, exist_ok=True)
        feats.to_parquet(out_f, index=False)
        print(f"[done] window {win}s: {len(feats)} processes "
              f"({int(feats['label'].sum())} malicious) -> {out_f}")

    max_len = int(config["features"]["sequence_max_len"])
    win = int(config["models"]["feature_window_s"])
    ids, X, y = build_sequences(df, max_len, config["features"]["sequence_pad"], window_s=win)
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
