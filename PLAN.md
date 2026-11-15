# Thesis_work — Implementation Plan

**Topic:** Виявлення шкідливих процесів за допомогою штучного інтелекту
**Author:** Щербак Є. П., група КББІ-21
**Basis:** Practice report, section 1.7 "Концепція системи виявлення шкідливих процесів"

---

## 1. Purpose

This document defines a minimal software implementation of the malicious process detection system described in Fig. 1.2 of the report. The implementation consists of seven files covering the full cycle: laboratory automation, data collection, feature formation, model training and evaluation, and real-time detection.

---

## 2. Repository structure

```
Thesis_work/
├── config.yaml
├── lab.py
├── scenarios.py
├── collector.py
├── features.py
├── models.py
└── detect.py
```

Runtime data is stored in `data/` (created automatically, excluded from version control). The Sysmon configuration is taken unchanged from the public sysmon-modular project and is not part of the codebase.

---

## 3. File descriptions

### 3.1. `config.yaml` — configuration

- Paths to data, logs and trained models
- VirtualBox VM name, clean snapshot name, guest credentials
- Scenario registry: name, class (benign / malicious), source, ATT&CK technique, duration
- Feature window sizes (10 s, 30 s)
- Model hyperparameters and decision thresholds

### 3.2. `lab.py` — virtual laboratory automation

- Wrapper over `VBoxManage`: start, stop, execute in guest, copy files
- Restore the clean snapshot before every run
- Execute a scenario in the guest and record the seed ProcessGuid
- Export Sysmon EVTX logs to `data/raw/<run_id>/`
- Batch mode: iterate over all scenarios in `config.yaml`

### 3.3. `scenarios.py` — scenario implementations (runs inside the guest)

**Benign workloads:** office document editing, web browsing, software compilation, legitimate PowerShell administration, software installation.

**Behavioral simulators of harmful activity:**

| Simulator | Reproduced behavior | Threat class |
|---|---|---|
| `cpu_hog` | Sustained multi-core CPU exhaustion | Cryptominers, DoS |
| `memory_hog` | Memory ballooning and leak pattern | Resource exhaustion |
| `io_thrash` | Intensive random disk read/write | Disk-based DoS |
| `thread_bomb` | Rapid creation of threads and handles | Resource exhaustion |
| `file_churn` | Mass write, rename and delete on a generated test corpus with reversible transformation | Ransomware I/O pattern |
| `connection_flood` | Many outbound connections to an internal sink host | Scanning, worms |
| `miner_like` | CPU-bound computation with periodic network beaconing | Cryptominers, C2 beaconing |

**External sources (launchers only):**
- Atomic Red Team tests by ATT&CK technique ID (T1055, T1059, T1218)
- Documented malware samples from public research repositories (MalwareBazaar, VirusShare, MalShare, theZoo)
- EICAR test file for pipeline validation

### 3.4. `collector.py` — telemetry processing and labeling

- Parse Sysmon EVTX files (`python-evtx`)
- Normalize events to a common schema: timestamp, ProcessGuid, PID, PPID, image, command line, event type, target, user, integrity level
- Label processes: the seed process of a malicious scenario and all its descendants are malicious, all other processes are benign
- Save labelled events to `data/events.parquet`

### 3.5. `features.py` — feature formation

- Process tree reconstruction keyed by ProcessGuid (handles PID reuse)
- Fixed-length feature vector over the first N seconds of process life, covering the seven groups of Table 1.2: static attributes, launch context, API activity, file and registry activity, network activity, resource metrics, inter-process interaction
- Command-line encoders: length, entropy, character n-grams
- Event-token sequences per process for the LSTM model
- Save to `data/features.parquet` and `data/sequences.pkl`

### 3.6. `models.py` — training and evaluation

- Time-based train/test split (TESSERACT methodology [15])
- Stage 1: XGBoost classifier on window features
- Stage 2: PyTorch LSTM classifier on event sequences
- Anomaly detection: Isolation Forest trained on benign data only
- Decision fusion with aggregation at process-tree level
- Metrics: precision, recall, F1, ROC-AUC, FPR, recall at FPR ≤ 0.1 %, time to detection
- SHAP feature attributions [17]
- Export of tables and figures for the thesis; trained models saved to `data/models/`

### 3.7. `detect.py` — real-time detection prototype

- Read the live Sysmon event log
- Incremental process tree and feature updates
- Inference: stage 1 → stage 2 for suspicious processes → decision fusion
- Alert output: score, event chain, top contributing features
- Response policy: notify, suspend process, terminate process

---

## 4. Data collection strategy

| Class | Sources |
|---|---|
| Benign | Realistic workloads, including activity superficially similar to malicious (PowerShell administration, installers, high CPU load) |
| Malicious | Behavioral simulators, Atomic Red Team emulation, documented malware samples |

Evaluation protocol:
- Time-based train/test split [15]
- Realistic class ratio in the test set
- Selected malware families and techniques excluded from training to measure generalization [16]
- Results reported separately per data source

Samples that detect the virtual environment and suppress execution are recorded as an observed limitation of dynamic analysis (report section 1.4).

---

## 5. Laboratory safety requirements

- VM network: internal or host-only; NAT and bridged modes prohibited
- All network targets are a sink VM within the internal network
- Shared folders, shared clipboard and drag-and-drop disabled
- Clean snapshot restored before every run
- Malware samples stored in password-protected archives, never executed or extracted on the host

---

## 6. Development stages

| Stage | File | Completion criterion |
|---|---|---|
| 1 | `config.yaml`, `lab.py` | Automated cycle: snapshot restore → scenario → EVTX export |
| 2 | `scenarios.py` | Benign workloads and simulators run in the guest; EICAR test passes |
| 3 | `collector.py` | Labelled normalized events produced |
| 4 | `features.py` | Feature vectors and sequences produced; PID reuse handled |
| 5 | `models.py` | Three models trained and evaluated; SHAP explanations generated |
| 6 | `detect.py` | Real-time detection with explained alerts |
| 7 | `scenarios.py` | Malicious class extended with emulation and real samples; generalization reported |

---

## 7. Dependencies

**Python 3.11+:** `xgboost`, `scikit-learn`, `torch`, `pandas`, `pyarrow`, `python-evtx`, `shap`, `pyyaml`, `matplotlib`

**Guest system:** Windows 10/11, Sysmon (sysmon-modular configuration), Invoke-AtomicRedTeam

**Host system:** Oracle VirtualBox with `VBoxManage`

---

## 8. References

[15] Pendlebury F. et al. TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time. USENIX Security, 2019.
[16] Arp D. et al. Dos and Don'ts of Machine Learning in Computer Security. USENIX Security, 2022.
[17] Lundberg S. M., Lee S.-I. A Unified Approach to Interpreting Model Predictions. NeurIPS, 2017.
