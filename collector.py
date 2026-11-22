from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional

import pandas as pd
import yaml

SCHEMA = [
    "ts", "run_id", "scenario", "kind", "event_id",
    "process_guid", "pid", "image", "command_line", "user", "integrity_level",
    "parent_guid", "ppid", "parent_image", "hashes",
    "signed", "signature_status", "image_loaded",
    "dest_ip", "dest_port", "protocol",
    "target_guid", "granted_access",
    "target_filename", "reg_target", "reg_details", "dns_query",
    "label",
]

_NS = re.compile(r"\{.*?\}")


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def parse_evtx(evtx_path: Path) -> Iterator[Dict[str, object]]:
    import xml.etree.ElementTree as ET

    from Evtx.Evtx import Evtx

    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue
            for el in root.iter():
                el.tag = _NS.sub("", el.tag)

            system = root.find("System")
            if system is None:
                continue
            eid_el = system.find("EventID")
            if eid_el is None or eid_el.text is None:
                continue
            try:
                event_id = int(eid_el.text)
            except ValueError:
                continue

            data: Dict[str, str] = {}
            event_data = root.find("EventData")
            if event_data is not None:
                for d in event_data.findall("Data"):
                    name = d.get("Name")
                    if name:
                        data[name] = d.text
            yield {"event_id": event_id, "data": data}


def _ts(data: Dict[str, str]) -> Optional[str]:
    return data.get("UtcTime")


def normalize_record(raw: Dict[str, object], run_id: str,
                     scenario: str, kind: str) -> Optional[Dict[str, object]]:
    eid = raw["event_id"]
    d: Dict[str, str] = raw["data"]

    row = {k: None for k in SCHEMA}
    row.update(run_id=run_id, scenario=scenario, kind=kind,
               event_id=eid, ts=_ts(d))

    if eid == 1:
        row.update(
            process_guid=d.get("ProcessGuid"), pid=d.get("ProcessId"),
            image=d.get("Image"), command_line=d.get("CommandLine"),
            user=d.get("User"), integrity_level=d.get("IntegrityLevel"),
            parent_guid=d.get("ParentProcessGuid"), ppid=d.get("ParentProcessId"),
            parent_image=d.get("ParentImage"), hashes=d.get("Hashes"),
        )
    elif eid == 3:
        row.update(
            process_guid=d.get("ProcessGuid"), pid=d.get("ProcessId"),
            image=d.get("Image"), dest_ip=d.get("DestinationIp"),
            dest_port=d.get("DestinationPort"), protocol=d.get("Protocol"),
        )
    elif eid == 7:
        row.update(
            process_guid=d.get("ProcessGuid"), image=d.get("Image"),
            image_loaded=d.get("ImageLoaded"), signed=d.get("Signed"),
            signature_status=d.get("SignatureStatus"),
        )
    elif eid == 8:
        row.update(
            process_guid=d.get("SourceProcessGuid"), image=d.get("SourceImage"),
            target_guid=d.get("TargetProcessGuid"),
        )
    elif eid == 10:
        row.update(
            process_guid=d.get("SourceProcessGuid"), image=d.get("SourceImage"),
            target_guid=d.get("TargetProcessGuid"),
            granted_access=d.get("GrantedAccess"),
            target_filename=d.get("TargetImage"),
        )
    elif eid == 11:
        row.update(
            process_guid=d.get("ProcessGuid"), image=d.get("Image"),
            target_filename=d.get("TargetFilename"),
        )
    elif eid == 13:
        row.update(
            process_guid=d.get("ProcessGuid"), image=d.get("Image"),
            reg_target=d.get("TargetObject"), reg_details=d.get("Details"),
        )
    elif eid == 12:
        row.update(
            process_guid=d.get("ProcessGuid"), image=d.get("Image"),
            reg_target=d.get("TargetObject"), reg_details=d.get("EventType"),
        )
    elif eid == 5:
        row.update(process_guid=d.get("ProcessGuid"), pid=d.get("ProcessId"),
                   image=d.get("Image"))
    elif eid == 22:
        row.update(process_guid=d.get("ProcessGuid"), pid=d.get("ProcessId"),
                   image=d.get("Image"), dns_query=d.get("QueryName"))
    elif eid in (23, 26):
        row.update(process_guid=d.get("ProcessGuid"), image=d.get("Image"),
                   target_filename=d.get("TargetFilename"))
    else:
        return None
    return row


def malicious_guids(events: List[Dict[str, object]], seed_guid: str) -> set:
    children: Dict[str, List[str]] = {}
    injected: Dict[str, List[str]] = {}
    for e in events:
        if e["event_id"] == 1 and e["parent_guid"] and e["process_guid"]:
            children.setdefault(e["parent_guid"], []).append(e["process_guid"])
        elif e["event_id"] == 8 and e["process_guid"] and e["target_guid"]:
            injected.setdefault(e["process_guid"], []).append(e["target_guid"])

    seen = set()
    stack = [seed_guid]
    while stack:
        g = stack.pop()
        if g in seen:
            continue
        seen.add(g)
        stack.extend(children.get(g, []))
        stack.extend(injected.get(g, []))
    return seen


def label_events(events: List[Dict[str, object]], meta: dict) -> None:
    if meta.get("label") == "malicious" and meta.get("seed_guid"):
        bad = malicious_guids(events, meta["seed_guid"])
        for e in events:
            e["label"] = 1 if e["process_guid"] in bad else 0
    else:
        for e in events:
            e["label"] = 0


def load_run(run_dir: Path) -> List[Dict[str, object]]:
    meta_path = run_dir / "meta.json"
    if not meta_path.exists():
        raise FileNotFoundError(f"no meta.json in {run_dir}")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    evtx_files = sorted(run_dir.glob("*.evtx"))
    if not evtx_files:
        raise FileNotFoundError(f"no .evtx in {run_dir}")

    events: List[Dict[str, object]] = []
    for evtx in evtx_files:
        for raw in parse_evtx(evtx):
            row = normalize_record(raw, meta["run_id"],
                                   meta.get("scenario", ""), meta.get("kind", ""))
            if row is not None:
                events.append(row)

    label_events(events, meta)
    return events


def _parse_run_cached(args) -> tuple:
    rd, cache_dir = Path(args[0]), Path(args[1])
    cache = cache_dir / f"{rd.name}.parquet"
    try:
        src_mtime = max(p.stat().st_mtime for p in [rd / "meta.json", *rd.glob("*.evtx")])
    except (ValueError, FileNotFoundError):
        return rd.name, None, "no meta.json or .evtx"
    if cache.exists() and cache.stat().st_mtime >= src_mtime:
        return rd.name, str(cache), "cached"
    try:
        events = load_run(rd)
    except FileNotFoundError as exc:
        return rd.name, None, str(exc)
    frame = pd.DataFrame(events, columns=SCHEMA)
    for col in ("pid", "ppid", "dest_port"):
        frame[col] = pd.to_numeric(frame[col], errors="coerce")
    frame = frame.astype({c: "string" for c in SCHEMA
                          if c not in ("event_id", "pid", "ppid", "dest_port", "label")})
    frame.to_parquet(cache, index=False)
    return rd.name, str(cache), f"{len(events)} events"


def build_events(config: dict, workers: int = 0) -> pd.DataFrame:
    import os
    from concurrent.futures import ProcessPoolExecutor

    raw_root = Path(config["paths"]["raw"])
    run_dirs = [p for p in sorted(raw_root.glob("*")) if p.is_dir()]
    if not run_dirs:
        raise RuntimeError(f"no run directories under {raw_root}")
    cache_dir = Path(config["paths"]["data_root"]) / "parsed"
    cache_dir.mkdir(parents=True, exist_ok=True)

    frames = []
    workers = workers or max((os.cpu_count() or 2) - 2, 1)
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for name, path, msg in ex.map(_parse_run_cached,
                                      [(str(rd), str(cache_dir)) for rd in run_dirs]):
            if path is None:
                print(f"[skip] {name}: {msg}")
                continue
            frames.append(pd.read_parquet(path))
            print(f"[ok]   {name}: {msg}")

    if not frames:
        raise RuntimeError("no runs could be parsed (missing meta.json or .evtx)")
    df = pd.concat(frames, ignore_index=True)
    df["ts"] = pd.to_datetime(df["ts"], errors="coerce", utc=True)
    df = df.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)
    for col in ("pid", "ppid", "dest_port"):
        df[col] = pd.to_numeric(df[col], errors="coerce")

    out = Path(config["paths"]["events"])
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    print(f"[done] {len(df)} events -> {out}")
    return df


def main() -> None:
    ap = argparse.ArgumentParser(description="Parse and label Sysmon telemetry.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--run", help="process only this run_id under data/raw")
    args = ap.parse_args()

    config = load_config(args.config)
    if args.run:
        run_dir = Path(config["paths"]["raw"]) / args.run
        events = load_run(run_dir)
        df = pd.DataFrame(events, columns=SCHEMA)
        print(df["label"].value_counts(dropna=False))
    else:
        build_events(config)


if __name__ == "__main__":
    main()
