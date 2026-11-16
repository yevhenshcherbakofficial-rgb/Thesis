# Laboratory setup

How to build the isolated VirtualBox stand, install the guest telemetry and
tooling, and run the first data collection pass. Read this before running
`lab.py`.

> **Safety first.** Malware samples are executed in this VM. The whole point of
> the setup below is that nothing the guest does can reach your host or the
> network. Do not skip the network isolation steps.

---

## 1. Host prerequisites

- Oracle VirtualBox with `VBoxManage` on `PATH`
- Python 3.11 on the host
- `pip install -r requirements.txt`

Confirm `VBoxManage --version` works from the same shell you will run `lab.py` in.

---

## 2. Guest virtual machine

Create a Windows 10 or 11 VM named exactly as `lab.vm_name` in `config.yaml`
(default `win10-detect`).

Recommended specs: 2 vCPU, 4 GB RAM, 60 GB disk. Install Guest Additions (the
`VBoxManage guestcontrol` commands in `lab.py` depend on them).

Create a throwaway local user matching `lab.guest_user` / `lab.guest_password`
in `config.yaml` (default `analyst` / `analyst`). These are lab-only credentials;
never reuse a real password.

### Network isolation (required)

Set the VM's adapter to **Internal Network** or **Host-Only**, never NAT or
Bridged:

```
VBoxManage modifyvm win10-detect --nic1 intnet --intnet1 "labnet"
```

If scenarios need a beacon/sink target (`conn_flood`, `miner_like`), run a second
tiny VM on the same `labnet` as the sink at `sandbox.sink_host` /
`sandbox.sink_port`. A simple listener is enough:

```
# on the sink VM
python -c "import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',9000));s.listen(50);[s.accept() for _ in iter(int,1)]"
```

Disable shared folders, shared clipboard and drag-and-drop:

```
VBoxManage modifyvm win10-detect --clipboard-mode disabled --draganddrop disabled
```

---

## 3. Guest software

Inside the VM:

1. **Python 3.11** at `lab.guest_python` (default `C:\Python311\python.exe`).
2. **PyYAML** in the guest interpreter: `pip install pyyaml`
   (`scenarios.py` only needs PyYAML; nothing heavy runs in the guest).
3. **Sysmon** with the sysmon-modular configuration:
   ```
   sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
   The config must log at least event IDs 1, 3, 7, 8, 10, 11, 13. Verify:
   ```
   wevtutil gl Microsoft-Windows-Sysmon/Operational
   ```
4. **Invoke-AtomicRedTeam** (only for the `atomic_*` scenarios):
   ```
   Install-Module -Name invoke-atomicredteam -Scope CurrentUser
   ```
5. Create the working and sandbox directories:
   `C:\lab` (`lab.guest_workdir`) and `C:\lab\sandbox` (`sandbox.file_dir`).

---

## 4. The clean snapshot

With the guest fully configured and **idle** (Sysmon running, log freshly
cleared), take the snapshot named in `config.yaml` (`lab.snapshot`, default
`clean`):

```
wevtutil cl Microsoft-Windows-Sysmon/Operational    # in the guest, then shut down
VBoxManage snapshot win10-detect take clean
```

`lab.py` restores this snapshot before every run, so each run starts from an
identical clean state with an empty Sysmon log.

---

## 5. Real malware samples

`scenarios.py` ships **no** malware. For `sample_run` scenarios you supply a
sample from a documented public repository (MalwareBazaar, VirusShare, MalShare,
theZoo). Store samples in password-protected archives outside the repo; extract
only inside the guest. Pass the in-guest path with `--sample`.

Validate the whole pipeline first with the harmless **EICAR** test file before
running any live sample.

Some samples detect the virtual environment and suppress execution; record these
and report them as a limitation of dynamic analysis (report section 1.4).

---

## 6. First collection pass

```
# one benign scenario end-to-end (sanity check)
python lab.py --scenario office_edit

# everything once
python lab.py --all

# three passes with varied timing (more data, time-split friendly)
python lab.py --all --repeat 3
```

Each run writes `data/raw/<run_id>/sysmon.evtx` and `meta.json`.

For a malicious run, confirm `meta.json` has a non-null `seed_guid`; if it is
null, labels for that run fall back to all-benign (a warning is printed).

---

## 7. Build the dataset and train

```
python collector.py      # data/raw/* -> data/events.parquet (parsed + labelled)
python features.py       # -> data/features.parquet + data/sequences.pkl
python models.py         # trains, evaluates, writes data/reports/metrics.json
```

Inspect `data/reports/metrics.json` (per-stage precision/recall/F1/ROC-AUC and
recall at the target FPR) and `data/reports/shap_importance.json`.

---

## 8. Real-time prototype

```
# replay a recorded run offline
python detect.py --replay data/raw/<run_id>/sysmon.evtx

# live, log-only (default)
python detect.py

# live with active response (use with care, lab only)
python detect.py --response terminate
```

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `VBoxManage failed: ... guestcontrol` | Guest Additions missing or wrong guest credentials |
| `seed not resolved` warning | Launcher command line not in the log; check Sysmon event ID 1 is enabled |
| `no .evtx in <run>` | `wevtutil epl` failed in guest; check the channel name |
| Empty / tiny dataset | Sysmon not logging the needed event IDs; re-check the config |
| One-class test metrics (NaN AUC) | Too few runs; collect more and use `--repeat` so the time split has both classes |
