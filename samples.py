"""
samples.py - Select and download documented malware samples from MalwareBazaar.

Runs on the HOST. Samples are stored exactly as MalwareBazaar serves them:
AES-encrypted ZIP archives (password "infected"). They are NEVER extracted on
the host; lab.py copies the archive into the isolated guest, where
scenarios.py extracts and runs it.

Storage (outside the git repository, see config.yaml `samples`):
    <samples.dir>/<sha256>.zip
    <samples.dir>/manifest.csv     one row per sample (family, sha256, ...)

The abuse.ch Auth-Key is read from `samples.auth_key_file` and only ever sent
in the Auth-Key request header.

CLI:
    python samples.py --list                    # show what would be selected
    python samples.py --download                # select + download per config
    python samples.py --download --per-family 3
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List

from collector import load_config

API = "https://mb-api.abuse.ch/api/v1/"
MANIFEST_FIELDS = ["sha256", "family", "file_name", "file_type", "file_size",
                   "first_seen", "tags", "archive", "downloaded_utc"]


def _key(cfg: dict) -> str:
    path = Path(cfg["samples"]["auth_key_file"])
    return path.read_text(encoding="utf-8").strip()


def _post(cfg: dict, fields: Dict[str, str], raw: bool = False):
    req = urllib.request.Request(
        API, data=urllib.parse.urlencode(fields).encode(),
        headers={"Auth-Key": _key(cfg), "User-Agent": "thesis-lab/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = resp.read()
    return body if raw else json.loads(body)


def query_family(cfg: dict, family: str, limit: int = 200) -> List[dict]:
    res = _post(cfg, {"query": "get_siginfo", "signature": family, "limit": str(limit)})
    if res.get("query_status") != "ok":
        return []
    return res.get("data") or []


def select(cfg: dict, per_family: int) -> List[dict]:
    """Pick recent Windows PE executables per family, smallest-first within the
    most recent ones (keeps total size low and avoids padded droppers)."""
    scfg = cfg["samples"]
    max_size = int(scfg.get("max_size_mb", 8)) * 1024 * 1024
    chosen: List[dict] = []
    for fam in scfg["families"]:
        rows = [r for r in query_family(cfg, fam)
                if r.get("file_type") == "exe" and int(r.get("file_size") or 0) <= max_size]
        rows.sort(key=lambda r: r.get("first_seen") or "", reverse=True)
        pick = rows[:per_family]
        print(f"  {fam:<16} available={len(rows):>3}  picked={len(pick)}")
        for r in pick:
            chosen.append({
                "sha256": r["sha256_hash"], "family": fam,
                "file_name": r.get("file_name") or f"{r['sha256_hash'][:12]}.exe",
                "file_type": r.get("file_type"), "file_size": r.get("file_size"),
                "first_seen": r.get("first_seen"),
                "tags": ";".join(r.get("tags") or []),
            })
        time.sleep(1)
    return chosen


def read_manifest(cfg: dict) -> List[dict]:
    path = Path(cfg["samples"]["dir"]) / "manifest.csv"
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def download(cfg: dict, chosen: List[dict]) -> None:
    out = Path(cfg["samples"]["dir"])
    out.mkdir(parents=True, exist_ok=True)
    have = {r["sha256"]: r for r in read_manifest(cfg)}
    for s in chosen:
        archive = out / f"{s['sha256']}.zip"
        if s["sha256"] in have and archive.exists():
            continue
        body = _post(cfg, {"query": "get_file", "sha256_hash": s["sha256"]}, raw=True)
        if not body.startswith(b"PK"):           # API answered with a JSON error
            print(f"  [skip] {s['family']} {s['sha256'][:16]}: {body[:120]!r}")
            continue
        archive.write_bytes(body)                # stays encrypted; never extracted here
        have[s["sha256"]] = {**s, "archive": archive.name,
                             "downloaded_utc": dt.datetime.utcnow().isoformat(timespec="seconds")}
        print(f"  [ok]   {s['family']:<16} {s['sha256'][:16]}  {len(body)} bytes")
        time.sleep(1)
    with (out / "manifest.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=MANIFEST_FIELDS)
        w.writeheader()
        for r in have.values():
            w.writerow({k: r.get(k, "") for k in MANIFEST_FIELDS})
    print(f"[done] {len(have)} samples in {out / 'manifest.csv'}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Select/download MalwareBazaar samples.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--list", action="store_true", help="only show the selection")
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--per-family", type=int)
    args = ap.parse_args()
    cfg = load_config(args.config)
    per = args.per_family or int(cfg["samples"]["per_family"])
    chosen = select(cfg, per)
    print(f"[select] {len(chosen)} samples")
    if args.download:
        download(cfg, chosen)
    elif args.list:
        for s in chosen:
            print(f"  {s['family']:<16} {s['sha256']}  {s['file_size']:>8}  {s['first_seen']}  {s['file_name']}")


if __name__ == "__main__":
    main()
