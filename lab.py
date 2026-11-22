from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import random
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Optional

from collector import load_config, parse_evtx

GUEST_EXPORT = "C:\\lab\\sysmon.evtx"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def now_tag() -> str:
    return dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def utcnow() -> str:
    return dt.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


class IsolationError(RuntimeError):
    pass


class VBox:
    def __init__(self, cfg: dict, vm: Optional[str] = None,
                 user: Optional[str] = None, password: Optional[str] = None):
        self.c = cfg["lab"]
        self.bin = self.c["vboxmanage"]
        self.vm = vm or self.c["vm_name"]
        self.user = user or self.c["guest_user"]
        self.password = password or self.c["guest_password"]

    def _run(self, *args: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
        cmd = [self.bin, *args]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if check and proc.returncode != 0:
            raise RuntimeError(f"VBoxManage failed: {' '.join(args)}\n{proc.stderr.strip()}")
        return proc

    def info(self) -> dict:
        out = self._run("showvminfo", self.vm, "--machinereadable").stdout
        res = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                res[k.strip('"')] = v.strip('"')
        return res

    def state(self) -> str:
        return self.info().get("VMState", "")

    def assert_isolated(self, network: str) -> None:
        i = self.info()
        problems = []
        if i.get("nic1") != "intnet" or i.get("intnet1") != network:
            problems.append(f"nic1={i.get('nic1')} intnet1={i.get('intnet1')}")
        for n in (2, 3, 4, 5, 6, 7, 8):
            v = i.get(f"nic{n}")
            if v not in (None, "none"):
                problems.append(f"nic{n}={v}")
        if problems:
            raise IsolationError(f"{self.vm} is not isolated on '{network}': {', '.join(problems)}")

    def guest_prop(self, name: str) -> str:
        out = self._run("guestproperty", "get", self.vm, name, check=False).stdout.strip()
        return out[len("Value: "):] if out.startswith("Value: ") else ""

    def restore(self) -> None:
        self._run("snapshot", self.vm, "restore", self.c["snapshot"])

    def start(self) -> None:
        self._run("startvm", self.vm, "--type", "headless")

    def poweroff(self) -> None:
        if self.state() in ("running", "paused", "stuck"):
            self._run("controlvm", self.vm, "poweroff", check=False)
            time.sleep(3)

    def _gc(self, *args: str, check: bool = True, timeout: int = 300):
        return self._run("guestcontrol", self.vm,
                         "--username", self.user, "--password", self.password,
                         *args, check=check, timeout=timeout)

    def copy_to(self, host_path: str, guest_path: str) -> None:
        sep = "/" if guest_path.startswith("/") else "\\"
        target = guest_path if guest_path.endswith(sep) else guest_path + sep
        self._gc("copyto", "--target-directory", target, str(Path(host_path).resolve()))

    def copy_from(self, guest_path: str, host_path: str) -> None:
        self._gc("copyfrom", guest_path, host_path)

    def run(self, exe: str, *args: str, timeout: int = 300) -> subprocess.CompletedProcess:
        return self._gc("run", "--exe", exe, "--", *args,
                        check=False, timeout=timeout)

    def wait_ready(self, timeout_s: int) -> float:
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            if self.guest_prop("/VirtualBox/GuestInfo/OS/LoggedInUsers") not in ("", "0"):
                r = self.run("C:\\Windows\\System32\\cmd.exe", "/c", "echo ready", timeout=60)
                if "ready" in (r.stdout or ""):
                    return time.time() - t0
            time.sleep(3)
        raise TimeoutError(f"{self.vm} not ready after {timeout_s}s")


def sink_box(cfg: dict) -> Optional[VBox]:
    lab = cfg["lab"]
    if not lab.get("sink_vm"):
        return None
    return VBox(cfg, vm=lab["sink_vm"], user=lab["sink_user"], password=lab["sink_password"])


def ensure_sink(cfg: dict) -> Optional[VBox]:
    sink = sink_box(cfg)
    if sink is None:
        return None
    sink.assert_isolated(cfg["lab"]["internal_network"])
    if sink.state() != "running":
        print(f"[sink] starting {sink.vm}")
        sink.start()
        t0 = time.time()
        while time.time() - t0 < 180:
            if sink.guest_prop("/VirtualBox/GuestAdd/Version"):
                break
            time.sleep(5)
        time.sleep(10)
    return sink


def save_sink_slice(sink: Optional[VBox], start: str, end: str, out_dir: Path) -> int:
    if sink is None:
        return 0
    with tempfile.TemporaryDirectory() as td:
        local = Path(td) / "sink.jsonl"
        try:
            sink.copy_from("/var/log/sink/sink.jsonl", str(local))
        except Exception as exc:
            print(f"[sink] log copy failed: {exc}")
            return 0
        keep = [ln for ln in local.read_text(encoding="utf-8", errors="replace").splitlines()
                if ln and start <= json.loads(ln).get("ts", "") <= end]
    (out_dir / "sink.jsonl").write_text("\n".join(keep) + ("\n" if keep else ""), encoding="utf-8")
    return len(keep)


def resolve_seed_guid(evtx_path: Path, tag: str) -> Optional[str]:
    for raw in parse_evtx(evtx_path):
        if raw["event_id"] != 1:
            continue
        cmd = (raw["data"].get("CommandLine") or "")
        if tag in cmd and "scenarios.py" in cmd:
            return raw["data"].get("ProcessGuid")
    return None


def samples_dir(cfg: dict) -> Path:
    return Path(cfg["samples"]["dir"])


def load_manifest(cfg: dict) -> List[dict]:
    path = samples_dir(cfg) / "manifest.csv"
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def run_scenario(vbox: VBox, cfg: dict, scenario: dict, here: Path,
                 sample: Optional[dict] = None, sink: Optional[VBox] = None) -> Path:
    lab = cfg["lab"]
    name = scenario["name"]
    run_id = f"{name}_{now_tag()}"
    if sample:
        run_id = f"{name}_{sample['family'].replace(' ', '')}_{sample['sha256'][:8]}_{now_tag()}"
    tag = secrets.token_hex(8)
    out_dir = Path(cfg["paths"]["raw"]) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    workdir = lab["guest_workdir"]
    guest_py = lab["guest_python"]
    duration = int(scenario.get("duration_s", 30))

    vbox.assert_isolated(lab["internal_network"])
    print(f"[run] {run_id} tag={tag}")
    vbox.restore()
    vbox.start()
    meta_extra: dict = {}
    t_start = t_end = None
    try:
        meta_extra["boot_ready_s"] = round(vbox.wait_ready(int(lab["boot_timeout_s"])), 1)
        time.sleep(int(lab["idle_wait_s"]))
        vbox.run("C:\\Windows\\System32\\wevtutil.exe", "sl", SYSMON_CHANNEL,
                 f"/ms:{int(lab.get('sysmon_log_max_mb', 1024)) * 1024 * 1024}", timeout=60)
        vbox.run("C:\\Windows\\System32\\wevtutil.exe", "cl", SYSMON_CHANNEL, timeout=60)

        vbox.copy_to(str(here / "scenarios.py"), workdir)
        vbox.copy_to(str(here / "config.yaml"), workdir)
        job = {"scenario": scenario.get("entry", name), "duration": duration,
               "config": f"{workdir}\\config.yaml"}
        if scenario.get("kind") == "atomic":
            job["technique"] = scenario.get("technique", "")
        if sample:
            vbox.copy_to(str(samples_dir(cfg) / f"{sample['sha256']}.zip"), workdir)
            job["sample_archive"] = f"{workdir}\\{sample['sha256']}.zip"
            job["sample_name"] = sample.get("file_name") or sample["sha256"][:12]
        with tempfile.TemporaryDirectory() as td:
            jf = Path(td) / f"{tag}.json"
            jf.write_text(json.dumps(job), encoding="utf-8")
            vbox.copy_to(str(jf), workdir)

        vbox.copy_to(str(here / "infra" / "resources.ps1"), workdir)
        sample_s = duration + int(lab["settle_wait_s"]) + 45
        vbox._gc("start", "--exe",
                 "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "--",
                 "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", f"{workdir}\\resources.ps1",
                 "-Out", f"{workdir}\\resources.csv", "-Seconds", str(sample_s),
                 check=False, timeout=60)
        time.sleep(3)

        t_start = utcnow()
        r = vbox.run(guest_py, f"{workdir}\\scenarios.py", "--job", f"{workdir}\\{tag}.json",
                     "--tag", tag, timeout=duration + 180)
        t_end = utcnow()
        meta_extra["scenario_output"] = ((r.stdout or "") + (r.stderr or "")).strip()[-1500:]
        time.sleep(int(lab["settle_wait_s"]))

        vbox.run("C:\\Windows\\System32\\wevtutil.exe", "epl", SYSMON_CHANNEL,
                 GUEST_EXPORT, "/ow:true", timeout=120)
        vbox.copy_from(GUEST_EXPORT, str(out_dir / "sysmon.evtx"))
        try:
            vbox.copy_from(f"{workdir}\\resources.csv", str(out_dir / "resources.csv"))
        except Exception as exc:
            print(f"[warn] resources.csv not copied: {exc}")
    finally:
        vbox.poweroff()

    if t_start and t_end:
        meta_extra["sink_records"] = save_sink_slice(sink, t_start, utcnow(), out_dir)

    seed = resolve_seed_guid(out_dir / "sysmon.evtx", tag) \
        if (out_dir / "sysmon.evtx").exists() else None
    meta = {
        "run_id": run_id, "scenario": name, "kind": scenario.get("kind"),
        "label": scenario.get("label"), "technique": scenario.get("technique"),
        "attack": scenario.get("attack"), "seed_guid": seed, "tag": tag,
        "duration_s": duration, "scenario_start_utc": t_start, "scenario_end_utc": t_end,
        "created_utc": dt.datetime.utcnow().isoformat(),
        "family": sample["family"] if sample else None,
        "sha256": sample["sha256"] if sample else None,
        "sample_file_name": sample.get("file_name") if sample else None,
        "sample_first_seen": sample.get("first_seen") if sample else None,
        **meta_extra,
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[run] {run_id} seed={seed} sink={meta.get('sink_records')}")
    if scenario.get("label") == "malicious" and not seed:
        print(f"[warn] {run_id}: seed not resolved; labels will be all-benign")
    return out_dir


def build_plan(cfg: dict, passes: int, seed: int = 42) -> List[dict]:
    rng = random.Random(seed)
    base = [s for s in cfg["scenarios"] if s.get("kind") != "sample"]
    sample_sc = next((s for s in cfg["scenarios"] if s.get("kind") == "sample"), None)
    samples = load_manifest(cfg) if sample_sc else []
    rng.shuffle(samples)
    plan: List[dict] = []
    for p in range(passes):
        chunk = [{"scenario": s["name"]} for s in base]
        chunk += [{"scenario": sample_sc["name"], "sha256": s["sha256"]}
                  for s in samples[p::passes]]
        rng.shuffle(chunk)
        plan += [{**c, "pass": p + 1} for c in chunk]
    for i, j in enumerate(plan):
        j["id"] = i
    return plan


def mark_unresolved_for_rerun(cfg: dict, state: dict) -> int:
    raw = Path(cfg["paths"]["raw"])
    aside = Path(cfg["paths"]["data_root"]) / "raw_unresolved"
    n = 0
    for job in state["plan"]:
        rid = job.get("run_id")
        if job.get("status") != "done" or not rid or not (raw / rid / "meta.json").exists():
            continue
        m = json.loads((raw / rid / "meta.json").read_text(encoding="utf-8"))
        if m.get("label") == "malicious" and not m.get("seed_guid"):
            aside.mkdir(parents=True, exist_ok=True)
            (raw / rid).rename(aside / rid)
            job.update(status="rerun", previous_run_id=rid)
            n += 1
    return n


def run_campaign(cfg: dict, here: Path, passes: int, rerun_unresolved: bool = False) -> None:
    state_path = Path(cfg["paths"]["data_root"]) / "campaign.json"
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if rerun_unresolved:
            print(f"[campaign] re-queued {mark_unresolved_for_rerun(cfg, state)} unresolved malicious runs")
        print(f"[campaign] resuming: {sum(j.get('status') == 'done' for j in state['plan'])}"
              f"/{len(state['plan'])} done")
    else:
        state = {"created_utc": dt.datetime.utcnow().isoformat(), "passes": passes,
                 "plan": build_plan(cfg, passes)}
    by_name = {s["name"]: s for s in cfg["scenarios"]}
    by_sha = {s["sha256"]: s for s in load_manifest(cfg)}
    vbox = VBox(cfg)
    sink = ensure_sink(cfg)

    def save():
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    save()
    todo = [j for j in state["plan"] if j.get("status") != "done"]
    for n, job in enumerate(todo, 1):
        sc = by_name[job["scenario"]]
        sample = by_sha.get(job.get("sha256")) if job.get("sha256") else None
        print(f"[campaign] {n}/{len(todo)} pass {job['pass']}: {job['scenario']}"
              + (f" {sample['family']}" if sample else ""))
        for attempt in (1, 2):
            try:
                out = run_scenario(vbox, cfg, sc, here, sample=sample, sink=sink)
                job.update(status="done", run_id=out.name, attempts=attempt)
                break
            except IsolationError:
                save(); raise
            except Exception as exc:
                print(f"[error] {job['scenario']} attempt {attempt}: {exc}")
                vbox.poweroff()
                job.update(status="failed", error=str(exc)[-500:], attempts=attempt)
        save()
    print(f"[campaign] finished: {sum(j.get('status') == 'done' for j in state['plan'])}"
          f"/{len(state['plan'])} done")


def main() -> None:
    ap = argparse.ArgumentParser(description="Collect labelled runs via VirtualBox.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--scenario", help="run only this scenario name")
    ap.add_argument("--all", action="store_true", help="run every non-sample scenario")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--sample-sha", help="run the sample_run scenario with this manifest sample")
    ap.add_argument("--campaign", action="store_true", help="interleaved resumable collection")
    ap.add_argument("--passes", type=int, default=5)
    ap.add_argument("--rerun-unresolved", action="store_true",
                    help="with --campaign: re-queue malicious runs whose seed was not resolved")
    args = ap.parse_args()

    cfg = load_config(args.config)
    here = Path(__file__).resolve().parent
    if args.campaign:
        run_campaign(cfg, here, args.passes, args.rerun_unresolved)
        return

    vbox = VBox(cfg)
    sink = ensure_sink(cfg)
    if args.sample_sha:
        sample = next((s for s in load_manifest(cfg) if s["sha256"].startswith(args.sample_sha)), None)
        if not sample:
            raise SystemExit(f"no manifest sample {args.sample_sha}")
        sc = next(s for s in cfg["scenarios"] if s.get("kind") == "sample")
        run_scenario(vbox, cfg, sc, here, sample=sample, sink=sink)
        return

    scenarios = [s for s in cfg["scenarios"] if s.get("kind") != "sample"]
    if args.scenario:
        scenarios = [s for s in cfg["scenarios"] if s["name"] == args.scenario]
        if not scenarios:
            raise SystemExit(f"no scenario named {args.scenario}")
    elif not args.all:
        raise SystemExit("specify --scenario, --all, --sample-sha or --campaign")

    for _ in range(args.repeat):
        for sc in scenarios:
            try:
                run_scenario(vbox, cfg, sc, here, sink=sink)
            except IsolationError:
                raise
            except Exception as exc:
                print(f"[error] {sc['name']}: {exc}")
                vbox.poweroff()


if __name__ == "__main__":
    main()
