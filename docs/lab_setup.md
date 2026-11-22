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
(default `win11-detect`).

Recommended specs: 2 vCPU, 8 GB RAM, 80 GB disk. Windows 11 also needs EFI, TPM 2.0 and Secure Boot enabled on the VM. Install Guest Additions (the
`VBoxManage guestcontrol` commands in `lab.py` depend on them).

Create a throwaway local user matching `lab.guest_user` / `lab.guest_password`
in `config.yaml` (default `analyst` / `analyst`). These are lab-only credentials;
never reuse a real password.

### Network isolation (required)

Set the VM's adapter to **Internal Network** or **Host-Only**, never NAT or
Bridged:

```
VBoxManage modifyvm win11-detect --nic1 intnet --intnet1 "labnet"
```

**Sink VM (`lab-sink`, 10.0.0.2).** A second small VM on `labnet` gives guest
traffic somewhere to go: Debian 13 netinst (unattended install, 1 vCPU, 512 MB,
8 GB), then copy `infra/sink.py` and `infra/sink_setup.sh` into it and run
`sudo sh sink_setup.sh`. It sets the static address, installs `sink.service`
(DNS on UDP 53 answers every A query with 10.0.0.2; a catch-all TCP listener
answers HTTP with 200) and an nftables rule that redirects every inbound TCP
port and UDP 53 to the sink. Every query/connection is logged to
`/var/log/sink/sink.jsonl`; `lab.py` stores the slice for each run as
`sink.jsonl`. Attach it to `labnet` only. `lab.py` starts it if it is off.

**Guest address.** Static `10.0.0.10/24`, default gateway and DNS `10.0.0.2`,
so lookups and connections to hard-coded IPs both reach the sink.

Disable shared folders, shared clipboard and drag-and-drop:

```
VBoxManage modifyvm win11-detect --clipboard-mode disabled --drag-and-drop disabled
```

---

## 3. Guest software

Inside the VM:

1. **Python 3.11** at `lab.guest_python` (default `C:\Python311\python.exe`).
2. **PyYAML** and **pyzipper** in the guest interpreter: `pip install pyyaml pyzipper`
   (pyzipper extracts the AES-encrypted sample archives inside the guest;
   install it offline from wheels if the guest has no network).
3. **Sysmon** with the sysmon-modular **excludes-only** configuration. Prebuilt
   configs are published as release assets (no longer in the repo tree):
   `https://github.com/olafhartong/sysmon-modular/releases/latest/download/sysmonconfig-excludes-only.xml`
   ```
   sysmon64.exe -accepteula -i sysmonconfig-excludes-only.xml
   ```
   Do not use the default `sysmonconfig.xml`: its ProcessCreate rules are
   include-based, so ordinary launches (including the `python scenarios.py`
   launcher) are not logged, the seed ProcessGuid cannot be resolved and the
   process tree has gaps.
   The config must log at least event IDs 1, 3, 7, 8, 10, 11, 13. Verify:
   ```
   wevtutil gl Microsoft-Windows-Sysmon/Operational
   ```
4. **Invoke-AtomicRedTeam** (only for the `atomic_*` scenarios):
   ```
   Install-Module -Name invoke-atomicredteam, powershell-yaml -Scope AllUsers -Force
   IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicsfolder.ps1' -UseBasicParsing)
   Install-AtomicsFolder -Force -InstallPath C:\AtomicRedTeam
   ```
   `AllUsers` is required because `scenarios.py` calls `Invoke-AtomicTest` from
   `powershell -NoProfile`; the atomics must be in the default
   `C:\AtomicRedTeam\atomics`. Disable Microsoft Defender in the guest first
   (Tamper Protection off in Windows Security, then real-time/behaviour
   monitoring off via policy), otherwise it quarantines the atomics binaries.
   Also disable UAC (`EnableLUA=0`) so `guestcontrol` commands get an admin token.
5. Create the working and sandbox directories:
   `C:\lab` (`lab.guest_workdir`) and `C:\lab\sandbox` (`sandbox.file_dir`).

---

## 4. The clean snapshot

With the guest fully configured and **idle** (Sysmon running, log freshly
cleared), take the snapshot named in `config.yaml` (`lab.snapshot`, default
`clean`):

```
wevtutil cl Microsoft-Windows-Sysmon/Operational    # in the guest, then shut down
VBoxManage snapshot win11-detect take clean
```

`lab.py` restores this snapshot before every run, so each run starts from an
identical clean state with an empty Sysmon log.

---

## 5. Real malware samples

`scenarios.py` ships **no** malware. `samples.py` selects recent Windows PE
samples per family (config `samples.families`) from MalwareBazaar and stores the
AES-encrypted ZIPs exactly as served, outside the repo (`samples.dir`), with a
`manifest.csv`. The abuse.ch Auth-Key is read from `samples.auth_key_file`.

```
python samples.py --list        # preview the selection
python samples.py --download
```

For a sample run, `lab.py` copies the encrypted ZIP into the guest; the
launcher extracts it there to `%USERPROFILE%\Downloads\<original name>.exe` and
runs it. Archives are never extracted on the host.

Validate the whole pipeline first with the harmless **EICAR** test file before
running any live sample.

Some samples detect the virtual environment and suppress execution; record these
and report them as a limitation of dynamic analysis (report section 1.4).

---

## 6. First collection pass

```
# one scenario end-to-end (sanity check)
python lab.py --scenario office_edit

# one real sample from the manifest (SHA-256 prefix)
python lab.py --sample-sha a0b5d730

# full collection: N passes of all scenarios, real samples spread across the
# passes, order shuffled per pass; resumable (state in data/campaign.json)
python lab.py --campaign --passes 5
```

Per run `lab.py`: refuses to start unless both VMs are attached only to
`lab.internal_network`; restores the snapshot; waits until the guest is
logged on and responsive plus `idle_wait_s`; clears the Sysmon log; starts
`infra/resources.ps1` (per-process CPU/memory/thread/handle sampler, 1 s);
runs the scenario via a job file and a random tag (so the launcher command line
carries no scenario name); exports the log; powers off.

Each run writes `data/raw/<run_id>/sysmon.evtx`, `resources.csv`,
`sink.jsonl` and `meta.json`.

For a malicious run, confirm `meta.json` has a non-null `seed_guid`; if it is
null, labels for that run fall back to all-benign (a warning is printed).

---

## 7. Build the dataset and train

```
python collector.py      # data/raw/* -> data/events.parquet (parsed + labelled, cached per run)
python features.py       # -> data/features.parquet (+ _w10) + data/sequences.pkl
python models.py         # trains, evaluates, writes data/reports/*
python results.py        # English results package -> results/ (tables, figures, README)
```

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
