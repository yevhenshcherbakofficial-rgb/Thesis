"""
lab.py - Virtual laboratory automation (runs on the HOST).

Drives VirtualBox via VBoxManage to produce labelled runs:

    for each scenario:
        restore clean snapshot -> boot -> copy in scenarios.py+config ->
        run scenario in guest -> export Sysmon log -> copy it out ->
        resolve seed ProcessGuid -> write meta.json -> power off

Output: data/raw/<run_id>/sysmon.evtx + meta.json  (consumed by collector.py)

Seed resolution: the guest launcher is `python scenarios.py ... --tag <run_id>`;
its ProcessCreate event carries the tag in its command line, so the root
ProcessGuid can be found unambiguously without tracking a PID.

Safety: this script assumes the VM's network is internal/host-only and a clean
snapshot exists. It never disables those; see docs/lab_setup.

CLI:
    python lab.py --all                 # run every scenario once
    python lab.py --scenario cpu_hog    # run one scenario
    python lab.py --all --repeat 3      # three passes (varied timing)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from collector import load_config, parse_evtx

GUEST_EXPORT = "C:\\lab\\sysmon.evtx"


def now_tag() -> str:
    return dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")


class VBox:
    def __init__(self, cfg: dict):
        self.c = cfg["lab"]
        self.bin = self.c["vboxmanage"]
        self.vm = self.c["vm_name"]

    def _run(self, *args: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
        cmd = [self.bin, *args]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if check and proc.returncode != 0:
            raise RuntimeError(f"VBoxManage failed: {' '.join(args)}\n{proc.stderr.strip()}")
        return proc

    # -- lifecycle ---------------------------------------------------------
    def restore(self) -> None:
        self._run("snapshot", self.vm, "restore", self.c["snapshot"])

    def start(self) -> None:
        self._run("startvm", self.vm, "--type", "headless")
        time.sleep(self.c["boot_wait_s"])

    def poweroff(self) -> None:
        self._run("controlvm", self.vm, "poweroff", check=False)
        time.sleep(3)

    # -- guest control -----------------------------------------------------
    def _gc(self, *args: str, check: bool = True, timeout: int = 300):
        return self._run("guestcontrol", self.vm,
                         "--username", self.c["guest_user"],
                         "--password", self.c["guest_password"],
                         *args, check=check, timeout=timeout)

    def copy_to(self, host_path: str, guest_path: str) -> None:
        self._gc("copyto", "--target-directory", guest_path, host_path)

    def copy_from(self, guest_path: str, host_path: str) -> None:
        self._gc("copyfrom", guest_path, host_path)

    def run(self, exe: str, *args: str, timeout: int = 300) -> None:
        self._gc("run", "--exe", exe, "--", exe, *args,
                 check=False, timeout=timeout)


def resolve_seed_guid(evtx_path: Path, tag: str) -> Optional[str]:
    """Find the ProcessGuid of the launcher whose command line carries the tag."""
    for raw in parse_evtx(evtx_path):
        if raw["event_id"] != 1:
            continue
        cmd = (raw["data"].get("CommandLine") or "")
        if tag in cmd and "scenarios.py" in cmd:
            return raw["data"].get("ProcessGuid")
    return None


def run_scenario(vbox: VBox, cfg: dict, scenario: dict, here: Path,
                 sample: Optional[str] = None) -> Path:
    name = scenario["name"]
    run_id = f"{name}_{now_tag()}"
    out_dir = Path(cfg["paths"]["raw"]) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    workdir = cfg["lab"]["guest_workdir"]
    guest_py = cfg["lab"]["guest_python"]
    duration = int(scenario.get("duration_s", 30))

    print(f"[run] {run_id}")
    vbox.restore()
    vbox.start()
    try:
        # Stage the scenario code and config into the guest.
        vbox.copy_to(str(here / "scenarios.py"), workdir)
        vbox.copy_to(str(here / "config.yaml"), workdir)

        # Build the scenario command.
        argv = ["--scenario", scenario.get("entry", name),
                "--duration", str(duration),
                "--tag", run_id,
                "--config", f"{workdir}\\config.yaml"]
        if scenario.get("kind") == "atomic":
            argv += ["--technique", scenario.get("technique", "")]
        if scenario.get("kind") == "sample" and sample:
            argv += ["--sample", sample]

        vbox.run(guest_py, f"{workdir}\\scenarios.py", *argv,
                 timeout=duration + 120)
        time.sleep(cfg["lab"]["settle_wait_s"])

        # Export the Sysmon operational log inside the guest, then copy it out.
        vbox.run("C:\\Windows\\System32\\wevtutil.exe", "epl",
                 "Microsoft-Windows-Sysmon/Operational", GUEST_EXPORT,
                 timeout=60)
        vbox.copy_from(GUEST_EXPORT, str(out_dir / "sysmon.evtx"))
    finally:
        vbox.poweroff()

    seed = resolve_seed_guid(out_dir / "sysmon.evtx", run_id) \
        if (out_dir / "sysmon.evtx").exists() else None
    meta = {
        "run_id": run_id, "scenario": name, "kind": scenario.get("kind"),
        "label": scenario.get("label"), "technique": scenario.get("technique"),
        "attack": scenario.get("attack"), "seed_guid": seed,
        "duration_s": duration, "created_utc": dt.datetime.utcnow().isoformat(),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[run] {run_id} seed={seed}")
    if scenario.get("label") == "malicious" and not seed:
        print(f"[warn] {run_id}: seed not resolved; labels will be all-benign")
    return out_dir


def main() -> None:
    ap = argparse.ArgumentParser(description="Collect labelled runs via VirtualBox.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--scenario", help="run only this scenario name")
    ap.add_argument("--all", action="store_true", help="run every scenario")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--sample", help="path to a sample for sample_run scenarios")
    args = ap.parse_args()

    cfg = load_config(args.config)
    here = Path(__file__).resolve().parent
    vbox = VBox(cfg)

    scenarios = cfg["scenarios"]
    if args.scenario:
        scenarios = [s for s in scenarios if s["name"] == args.scenario]
        if not scenarios:
            raise SystemExit(f"no scenario named {args.scenario}")
    elif not args.all:
        raise SystemExit("specify --scenario <name> or --all")

    for rep in range(args.repeat):
        for sc in scenarios:
            try:
                run_scenario(vbox, cfg, sc, here, sample=args.sample)
            except Exception as exc:
                print(f"[error] {sc['name']}: {exc}")
                vbox.poweroff()


if __name__ == "__main__":
    main()
