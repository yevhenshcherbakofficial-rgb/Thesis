"""
scenarios.py - Workloads and behavioral simulators (runs INSIDE the guest VM).

Three groups of scenarios generate the training telemetry:

  * workloads  - realistic benign activity (the negative class), including
                 activity that superficially resembles attacks (admin
                 PowerShell, installers, high CPU) so the false-positive rate
                 is measured honestly.
  * simulators - LOAD GENERATORS that reproduce the *resource / IO / network
                 signature* of harmful software. They are NOT malware: they do
                 not self-replicate, do not persist, touch only the configured
                 sandbox directory, and talk only to the configured internal
                 sink host. file_churn uses a reversible XOR over a generated
                 corpus; nothing real is ever encrypted.
  * launchers  - thin wrappers that invoke external, documented tooling
                 (Atomic Red Team) or a provided sample path. This file
                 contains no attack code of its own for those.

The launcher process (python.exe running this file) is the scenario's root; its
ProcessGuid is resolved by lab.py from the unique --tag on the command line and
recorded as seed_guid. Every descendant is labeled malicious for simulator /
atomic / sample runs.

CLI (invoked by lab.py in the guest):
    python scenarios.py --scenario cpu_hog --duration 30 --tag <run_id> --config config.yaml
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import yaml

IS_WINDOWS = os.name == "nt"


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _spawn(cmd: list[str]) -> None:
    """Run a child process to generate parent-child telemetry; ignore failures."""
    try:
        subprocess.run(cmd, timeout=20, capture_output=True)
    except Exception:
        pass


def _deadline(duration_s: int) -> float:
    return time.time() + duration_s


# ===========================================================================
# Benign workloads (negative class)
# ===========================================================================
def office_workload(duration_s: int, cfg: dict) -> None:
    tmp = Path(os.environ.get("TEMP", "/tmp")) / "office_work"
    tmp.mkdir(parents=True, exist_ok=True)
    end = _deadline(duration_s)
    i = 0
    while time.time() < end:
        (tmp / f"doc_{i}.txt").write_text("report draft " * 200)
        if IS_WINDOWS:
            _spawn(["cmd", "/c", "type", str(tmp / f"doc_{i}.txt")])
        i += 1
        time.sleep(1)


def browser_workload(duration_s: int, cfg: dict) -> None:
    host = cfg["sandbox"]["sink_host"]
    end = _deadline(duration_s)
    while time.time() < end:
        if IS_WINDOWS:
            _spawn(["powershell", "-NoProfile", "-Command",
                    f"try{{Invoke-WebRequest -UseBasicParsing http://{host}/ "
                    f"-TimeoutSec 2}}catch{{}}"])
        else:
            _spawn(["curl", "-s", "-m", "2", f"http://{host}/"])
        time.sleep(2)


def dev_workload(duration_s: int, cfg: dict) -> None:
    tmp = Path(os.environ.get("TEMP", "/tmp")) / "dev_work"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "m.py").write_text("print(sum(range(1000)))\n")
    end = _deadline(duration_s)
    while time.time() < end:
        _spawn([sys.executable, str(tmp / "m.py")])
        if IS_WINDOWS:
            _spawn(["cmd", "/c", "dir", str(tmp)])
        time.sleep(2)


def admin_powershell(duration_s: int, cfg: dict) -> None:
    # Legitimate administrative PowerShell - a deliberately hard benign sample.
    cmds = ["Get-Process | Select-Object -First 5",
            "Get-Service | Select-Object -First 5",
            "Get-ChildItem $env:TEMP | Select-Object -First 5"]
    end = _deadline(duration_s)
    i = 0
    while time.time() < end:
        c = cmds[i % len(cmds)]
        if IS_WINDOWS:
            _spawn(["powershell", "-NoProfile", "-Command", c])
        i += 1
        time.sleep(2)


def installer_workload(duration_s: int, cfg: dict) -> None:
    src = Path(os.environ.get("TEMP", "/tmp")) / "pkg_src"
    dst = Path(os.environ.get("TEMP", "/tmp")) / "pkg_install"
    src.mkdir(parents=True, exist_ok=True); dst.mkdir(parents=True, exist_ok=True)
    for i in range(20):
        (src / f"file_{i}.bin").write_bytes(os.urandom(4096))
    end = _deadline(duration_s)
    while time.time() < end:
        for f in src.glob("*.bin"):
            (dst / f.name).write_bytes(f.read_bytes())
        time.sleep(2)


# ===========================================================================
# Behavioral simulators (malicious class) - bounded load generators
# ===========================================================================
def cpu_hog(duration_s: int, cfg: dict) -> None:
    n = max(os.cpu_count() or 2, 2)
    stop = _deadline(duration_s)

    def burn():
        x = 0.0001
        while time.time() < stop:
            x = (x * 1.0000001 + 1.0) ** 0.5

    threads = [threading.Thread(target=burn) for _ in range(n)]
    for t in threads: t.start()
    for t in threads: t.join()


def memory_hog(duration_s: int, cfg: dict, cap_mb: int = 512) -> None:
    blocks, held = [], 0
    end = _deadline(duration_s)
    while time.time() < end and held < cap_mb:
        blocks.append(bytearray(8 * 1024 * 1024))   # 8 MB chunks
        held += 8
        time.sleep(0.2)
    time.sleep(max(end - time.time(), 0))
    del blocks                                       # release on exit


def io_thrash(duration_s: int, cfg: dict) -> None:
    sandbox = Path(cfg["sandbox"]["file_dir"]); sandbox.mkdir(parents=True, exist_ok=True)
    end = _deadline(duration_s)
    i = 0
    while time.time() < end:
        p = sandbox / f"io_{i % 50}.tmp"
        p.write_bytes(os.urandom(1024 * 1024))
        _ = p.read_bytes()
        i += 1


def thread_bomb(duration_s: int, cfg: dict, cap: int = 500) -> None:
    end = _deadline(duration_s)
    threads = []

    def idle():
        time.sleep(min(2, max(end - time.time(), 0)))

    while time.time() < end and len(threads) < cap:
        t = threading.Thread(target=idle); t.start()
        threads.append(t)
        time.sleep(0.01)
    for t in threads: t.join()


def file_churn(duration_s: int, cfg: dict, corpus: int = 200) -> None:
    """Ransomware-LIKE mass file I/O on a GENERATED corpus. Reversible XOR,
    confined to the sandbox directory; no real user data, no real encryption."""
    sandbox = Path(cfg["sandbox"]["file_dir"]) / "corpus"
    sandbox.mkdir(parents=True, exist_ok=True)
    for i in range(corpus):
        (sandbox / f"f_{i}.dat").write_bytes(os.urandom(2048))

    key = 0x5A
    end = _deadline(duration_s)
    while time.time() < end:
        for f in list(sandbox.glob("*.dat")):
            data = bytes(b ^ key for b in f.read_bytes())   # reversible
            enc = f.with_suffix(".locked")
            enc.write_bytes(data)
            f.unlink()
        for f in list(sandbox.glob("*.locked")):            # reverse it back
            data = bytes(b ^ key for b in f.read_bytes())
            f.with_suffix(".dat").write_bytes(data)
            f.unlink()


def connection_flood(duration_s: int, cfg: dict) -> None:
    host, port = cfg["sandbox"]["sink_host"], int(cfg["sandbox"]["sink_port"])
    end = _deadline(duration_s)
    while time.time() < end:
        for _ in range(20):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect((host, port))
                s.close()
            except OSError:
                pass
        time.sleep(0.5)


def miner_like(duration_s: int, cfg: dict) -> None:
    host, port = cfg["sandbox"]["sink_host"], int(cfg["sandbox"]["sink_port"])
    end = _deadline(duration_s)
    last_beacon = 0.0
    x = 1.0001
    while time.time() < end:
        for _ in range(100000):                      # CPU-bound mining proxy
            x = (x * 1.0000001 + 1.0) ** 0.5
        if time.time() - last_beacon > 5:            # periodic C2-style beacon
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3); s.connect((host, port))
                s.sendall(b"beacon"); s.close()
            except OSError:
                pass
            last_beacon = time.time()


# ===========================================================================
# External launchers (no attack code here)
# ===========================================================================
def run_atomic(duration_s: int, cfg: dict, technique: str) -> None:
    """Invoke Atomic Red Team for a technique id. Requires Invoke-AtomicRedTeam
    to be installed in the guest (see docs/lab_setup). The whole technique is
    bounded by duration_s; each test by a share of it."""
    if not IS_WINDOWS:
        print("atomic launcher requires the Windows guest"); return
    per_test = max(duration_s // 4, 10)
    try:
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                        f"Invoke-AtomicTest {technique} -TimeoutSeconds {per_test}"],
                       timeout=duration_s + 30, capture_output=True)
    except Exception as exc:
        print(f"atomic run ended: {exc}")


def extract_sample(archive: str, name: str, password: str) -> str:
    """Extract a MalwareBazaar AES ZIP inside the guest to the user's Downloads
    folder under its original file name (realistic launch location)."""
    import pyzipper                                   # installed in the guest only
    dest_dir = Path(os.environ.get("USERPROFILE", "C:\\Users\\Public")) / "Downloads"
    dest_dir.mkdir(parents=True, exist_ok=True)
    with pyzipper.AESZipFile(archive) as zf:
        zf.setpassword(password.encode())
        member = zf.namelist()[0]
        data = zf.read(member)
    stem = Path(name).stem if name else Path(member).stem
    dest = dest_dir / f"{stem}.exe"
    dest.write_bytes(data)
    os.remove(archive)
    return str(dest)


def run_sample(duration_s: int, cfg: dict, sample_path: str | None) -> None:
    """Execute a documented malware sample provided by path. The sample is
    supplied by the researcher; this file ships none. Runs only in the isolated
    VM (enforced by lab network configuration, not by this code)."""
    if not sample_path or not Path(sample_path).exists():
        print("no sample provided; set --sample <path>"); return
    try:
        p = subprocess.Popen([sample_path])
        time.sleep(duration_s)
        print(f"[sample] exit code after {duration_s}s: {p.poll()}")
        p.terminate()
    except Exception as exc:
        print(f"sample run failed: {exc}")


WORKLOADS = {
    "office_workload": office_workload, "browser_workload": browser_workload,
    "dev_workload": dev_workload, "admin_powershell": admin_powershell,
    "installer_workload": installer_workload,
}
SIMULATORS = {
    "cpu_hog": cpu_hog, "memory_hog": memory_hog, "io_thrash": io_thrash,
    "thread_bomb": thread_bomb, "file_churn": file_churn,
    "connection_flood": connection_flood, "miner_like": miner_like,
}


def dispatch(args, cfg: dict) -> None:
    name = args.scenario
    if name in WORKLOADS:
        WORKLOADS[name](args.duration, cfg)
    elif name in SIMULATORS:
        SIMULATORS[name](args.duration, cfg)
    elif name.startswith("atomic") or args.technique:
        run_atomic(args.duration, cfg, args.technique or name)
    elif name == "sample_run":
        run_sample(args.duration, cfg, args.sample)
    else:
        raise SystemExit(f"unknown scenario: {name}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Run one guest scenario.")
    ap.add_argument("--scenario")
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--tag", required=True, help="unique run id (seed resolution)")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--technique", help="ATT&CK id for atomic launcher")
    ap.add_argument("--sample", help="path to a sample for sample_run")
    ap.add_argument("--job", help="JSON job file with the arguments above (used by "
                                  "lab.py so the launcher command line carries no "
                                  "scenario name)")
    args = ap.parse_args()

    if args.job:
        import json
        job = json.loads(Path(args.job).read_text(encoding="utf-8"))
        args.scenario = job["scenario"]
        args.duration = int(job.get("duration", args.duration))
        args.technique = job.get("technique") or args.technique
        args.config = job.get("config", args.config)
        os.remove(args.job)
    cfg = load_config(args.config)
    if args.job and job.get("sample_archive"):
        args.sample = extract_sample(job["sample_archive"], job.get("sample_name", ""),
                                     cfg["samples"]["zip_password"])
    print(f"[scenario] {args.scenario} tag={args.tag} pid={os.getpid()}")
    dispatch(args, cfg)
    print(f"[scenario] {args.scenario} done")


if __name__ == "__main__":
    main()
