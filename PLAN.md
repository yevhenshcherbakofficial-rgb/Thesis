# Thesis\_work — Implementation Plan

**Topic:** Виявлення шкідливих процесів за допомогою штучного інтелекту
**Author:** Щербак Є. П., група КББІ-21
**Basis:** Practice report, section 1.7 "Концепція системи виявлення шкідливих процесів"

\---

## 1\. Purpose

This document defines the structure of the software implementation, the purpose of every file, the data collection strategy, laboratory safety requirements, and the order of development.

The system follows the architecture in Fig. 1.2 of the report:

1. Telemetry collection agent (Sysmon, ETW)
2. Feature formation module
3. Stage 1 classifier (gradient boosting)
4. Stage 2 analysis (LSTM) and anomaly detection (Isolation Forest)
5. Decision module with process-tree aggregation and explanations
6. Response module

\---

## 2\. Repository structure

```
Thesis\_work/
├── README.md
├── requirements.txt
├── environment.yml
├── .gitignore
│
├── config/
│   ├── settings.yaml
│   ├── sysmon-config.xml
│   ├── feature\_spec.yaml
│   └── scenarios.yaml
│
├── lab/
│   ├── vbox\_controller.py
│   ├── snapshot\_manager.py
│   ├── run\_scenario.py
│   ├── orchestrator.py
│   └── guest/
│       ├── guest\_agent.py
│       ├── install\_sysmon.ps1
│       └── collect\_logs.ps1
│
├── scenarios/
│   ├── benign/
│   │   ├── office\_workload.py
│   │   ├── browser\_workload.py
│   │   ├── dev\_workload.py
│   │   ├── admin\_powershell.py
│   │   └── installer\_workload.py
│   ├── malicious\_sim/
│   │   ├── cpu\_hog.py
│   │   ├── memory\_hog.py
│   │   ├── io\_thrash.py
│   │   ├── handle\_thread\_bomb.py
│   │   ├── file\_churn.py
│   │   ├── connection\_flood.py
│   │   └── miner\_like.py
│   ├── emulation/
│   │   ├── run\_atomic.ps1
│   │   ├── atomic\_tests.yaml
│   │   └── caldera\_adversary.yaml
│   └── real\_samples/
│       ├── README.md
│       ├── download\_samples.py
│       ├── sample\_manifest.csv
│       └── eicar\_smoketest.py
│
├── collector/
│   ├── schema.py
│   ├── evtx\_parser.py
│   ├── etw\_collector.py
│   └── normalizer.py
│
├── features/
│   ├── process\_tree.py
│   ├── window\_features.py
│   ├── sequence\_features.py
│   ├── graph\_features.py
│   ├── encoders.py
│   └── feature\_store.py
│
├── labeling/
│   ├── ground\_truth.py
│   └── label\_merge.py
│
├── datasets/
│   ├── build\_dataset.py
│   ├── temporal\_split.py
│   └── dataset\_card.md
│
├── models/
│   ├── base.py
│   ├── gbm\_stage1.py
│   ├── lstm\_stage2.py
│   ├── isolation\_forest.py
│   ├── decision\_fusion.py
│   └── registry.py
│
├── eval/
│   ├── metrics.py
│   ├── evaluate.py
│   ├── shap\_explain.py
│   └── report.py
│
├── prototype/
│   ├── realtime\_agent.py
│   ├── inference\_pipeline.py
│   ├── alert.py
│   └── response.py
│
├── notebooks/
│   ├── 01\_eda.ipynb
│   ├── 02\_feature\_analysis.ipynb
│   └── 03\_model\_comparison.ipynb
│
├── tests/
│   ├── test\_normalizer.py
│   ├── test\_process\_tree.py
│   ├── test\_window\_features.py
│   └── test\_temporal\_split.py
│
├── docs/
│   ├── architecture.md
│   ├── threat\_coverage\_attack.md
│   └── lab\_setup.md
│
└── data/
    ├── raw/
    ├── interim/
    ├── processed/
    └── models/
```

\---

## 3\. File descriptions

### 3.1. Root

|File|Purpose|
|-|-|
|`README.md`|Project overview, setup and run instructions|
|`requirements.txt`|Python dependencies|
|`environment.yml`|Conda environment definition|
|`.gitignore`|Excludes `data/`, trained models and malware samples from version control|

### 3.2. `config/`

|File|Purpose|
|-|-|
|`settings.yaml`|Global paths, VM names, snapshot names, time-window sizes (10 s, 30 s)|
|`sysmon-config.xml`|Sysmon configuration based on sysmon-modular; enables event IDs 1, 3, 7, 8, 10, 11, 13|
|`feature\_spec.yaml`|Declarative list of features for the seven groups of Table 1.2|
|`scenarios.yaml`|Registry of all scenarios with class, source, ATT\&CK technique and duration|

### 3.3. `lab/` — VirtualBox automation

|File|Purpose|
|-|-|
|`vbox\_controller.py`|Wrapper over `VBoxManage`: start, stop, execute in guest, copy files|
|`snapshot\_manager.py`|Restore the clean snapshot before each run|
|`run\_scenario.py`|Executes one scenario: restore → start → run → collect logs → power off|
|`orchestrator.py`|Iterates over `scenarios.yaml` and produces the full set of labelled runs|
|`guest/guest\_agent.py`|Guest-side agent: receives scenario ID, records the seed ProcessGuid, signals completion|
|`guest/install\_sysmon.ps1`|Installs and configures Sysmon in the guest|
|`guest/collect\_logs.ps1`|Exports Sysmon EVTX after the run|

### 3.4. `scenarios/` — data sources

|Directory|Class|Content|
|-|-|-|
|`benign/`|Benign|Office editing, web browsing, software development, legitimate PowerShell administration, software installation and updates|
|`malicious\_sim/`|Malicious|Behavioral simulators of harmful resource and file activity (see 4.1)|
|`emulation/`|Malicious|Atomic Red Team and MITRE Caldera scenarios mapped to MITRE ATT\&CK|
|`real\_samples/`|Malicious|Documented malware samples obtained from public research repositories|

### 3.5. `collector/` — telemetry processing

|File|Purpose|
|-|-|
|`schema.py`|Normalized event schema: timestamp, ProcessGuid, PID, PPID, image, command line, event type, target, user, integrity level|
|`evtx\_parser.py`|Parses exported Sysmon EVTX files (`python-evtx`)|
|`etw\_collector.py`|Optional live ETW collection (Kernel-Process, Kernel-File, Kernel-Network)|
|`normalizer.py`|Converts raw events into the normalized schema|

### 3.6. `features/` — feature formation

|File|Purpose|
|-|-|
|`process\_tree.py`|Maintains the process tree keyed by ProcessGuid; handles PID reuse|
|`window\_features.py`|Fixed-length feature vector over the first N seconds of process life|
|`sequence\_features.py`|Ordered event-token sequence per process for the LSTM model|
|`graph\_features.py`|Provenance subgraph per process (process – file – socket – registry)|
|`encoders.py`|Command-line entropy and length, n-grams, categorical encoding of parent-child pairs|
|`feature\_store.py`|Storage of feature tables in Parquet format|

### 3.7. `labeling/`

|File|Purpose|
|-|-|
|`ground\_truth.py`|Labels the seed process of a malicious scenario and all its descendants as malicious|
|`label\_merge.py`|Joins labels with feature rows|

### 3.8. `datasets/`

|File|Purpose|
|-|-|
|`build\_dataset.py`|Full pipeline: raw logs → events → features → labelled dataset|
|`temporal\_split.py`|Time-based train/test split following the TESSERACT methodology \[15]|
|`dataset\_card.md`|Dataset description: sources, class balance, time range, limitations|

### 3.9. `models/`

|File|Purpose|
|-|-|
|`base.py`|Common interface: `fit`, `predict\_proba`, `save`, `load`|
|`gbm\_stage1.py`|XGBoost first-stage classifier on window features|
|`lstm\_stage2.py`|PyTorch LSTM classifier on event sequences of suspicious processes|
|`isolation\_forest.py`|Anomaly detector trained on benign data only|
|`decision\_fusion.py`|Combines model scores and aggregates them at process-tree level|
|`registry.py`|Versioned storage of trained models|

### 3.10. `eval/`

|File|Purpose|
|-|-|
|`metrics.py`|Precision, recall, F1, ROC-AUC, FPR, recall at FPR ≤ 0.1 %, time to detection|
|`evaluate.py`|Evaluates all models on the temporal test set|
|`shap\_explain.py`|SHAP feature attributions \[17]|
|`report.py`|Generates tables and figures for the thesis|

### 3.11. `prototype/`

|File|Purpose|
|-|-|
|`realtime\_agent.py`|Reads the live Sysmon event log|
|`inference\_pipeline.py`|Features → stage 1 → stage 2 → decision fusion|
|`alert.py`|Alert structure: score, event chain, top contributing features|
|`response.py`|Response policy: notify, suspend process, terminate process|

### 3.12. `tests/`, `notebooks/`, `docs/`

|File|Purpose|
|-|-|
|`tests/test\_normalizer.py`|Schema conformity of normalized events|
|`tests/test\_process\_tree.py`|Correct tree reconstruction under PID reuse|
|`tests/test\_window\_features.py`|Correctness of aggregated feature values|
|`tests/test\_temporal\_split.py`|Absence of future data in the training set|
|`notebooks/01\_eda.ipynb`|Exploratory data analysis|
|`notebooks/02\_feature\_analysis.ipynb`|Feature importance and correlation analysis|
|`notebooks/03\_model\_comparison.ipynb`|Comparison of GBM, LSTM and Isolation Forest|
|`docs/architecture.md`|System architecture description (Fig. 1.2)|
|`docs/threat\_coverage\_attack.md`|Mapping of scenarios to MITRE ATT\&CK techniques|
|`docs/lab\_setup.md`|Virtual laboratory build and isolation procedure|

\---

## 4\. Data collection strategy

The malicious class is formed from three independent sources, and the benign class from a dedicated set of realistic workloads. Combining sources prevents the model from learning the characteristics of a single generator instead of malicious behavior \[16].

### 4.1. Behavioral simulators (`scenarios/malicious\_sim/`)

Simulators reproduce harmful resource and file activity characteristic of real threats, without self-replication and without access to data outside the virtual machine.

|Simulator|Reproduced behavior|Corresponding threat class|
|-|-|-|
|`cpu\_hog.py`|Sustained multi-core CPU exhaustion|Cryptominers, DoS|
|`memory\_hog.py`|Memory ballooning and leak pattern|Resource exhaustion|
|`io\_thrash.py`|Intensive random disk read/write|Disk-based DoS|
|`handle\_thread\_bomb.py`|Rapid creation of threads and handles|Resource exhaustion|
|`file\_churn.py`|Mass write, rename and delete operations on a generated test corpus with reversible transformation|Ransomware I/O pattern|
|`connection\_flood.py`|Large number of outbound connections to an internal sink host|Scanning, DoS, worms|
|`miner\_like.py`|CPU-bound computation with periodic network beaconing|Cryptominers, C2 beaconing|

### 4.2. Attack emulation (`scenarios/emulation/`)

Atomic Red Team and MITRE Caldera generate telemetry for the techniques listed in Table 1.1 of the report:

* T1055 — Process Injection
* T1059 — Command and Scripting Interpreter
* T1218 — System Binary Proxy Execution
* T1547 — Boot or Logon Autostart Execution
* T1543 — Create or Modify System Process

Caldera adversary profiles are used for multi-stage attack chains required for process-tree aggregation and provenance-graph analysis.

### 4.3. Real malware samples (`scenarios/real\_samples/`)

Samples are obtained from public malware repositories used in academic research:

|Repository|Access|
|-|-|
|MalwareBazaar (abuse.ch)|REST API with key; samples tagged by family and ATT\&CK technique|
|VirusShare|Access by request|
|MalShare|API with key|
|theZoo|Public GitHub repository|
|vx-underground|Public archive|

The EICAR test file is used to validate the full pipeline before running live samples. Each sample is recorded in `sample\_manifest.csv` with SHA-256, family, source and ATT\&CK tags.

Some samples are expected to detect the virtual environment and suppress execution. Such cases are recorded and discussed as an observed limitation of dynamic analysis (report section 1.4).

### 4.4. Benign workloads (`scenarios/benign/`)

Benign scenarios include activity that superficially resembles malicious behavior (PowerShell administration, installers, compilers, high CPU load) to ensure a realistic false positive rate.

### 4.5. Evaluation protocol

* Time-based train/test split \[15]
* Realistic class ratio in the test set
* Selected malware families and ATT\&CK techniques excluded from training to measure generalization to unseen threats
* Separate reporting of results per data source

\---

## 5\. Laboratory safety requirements

* Virtual machine network: internal or host-only; NAT and bridged modes are prohibited
* All network targets are a dedicated sink virtual machine within the internal network
* Shared folders, shared clipboard and drag-and-drop are disabled
* A clean snapshot is restored before every run
* Malware samples are stored in password-protected archives and are never executed or extracted on the host
* Samples and raw data are excluded from version control

\---

## 6\. Development stages

|Stage|Components|Completion criterion|
|-|-|-|
|1. Laboratory|`config/`, `lab/`, `docs/lab\_setup.md`|Automated cycle: snapshot restore → benign scenario → EVTX export|
|2. Collection|`collector/`|EVTX converted to normalized events conforming to `schema.py`|
|3. Features|`features/`, `tests/`|Window vectors and sequences produced; PID-reuse test passes|
|4. Scenarios and labels|`scenarios/benign/`, `scenarios/malicious\_sim/`, `labeling/`|Correctly labelled runs; EICAR smoke test passes|
|5. Dataset|`datasets/`|Temporal split without leakage|
|6. Models|`models/`|GBM, LSTM and Isolation Forest trained; decision fusion implemented|
|7. Evaluation|`eval/`|Metrics including recall at FPR ≤ 0.1 % and SHAP explanations|
|8. Prototype|`prototype/`|Real-time detection with explained alerts and response policy|
|9. Extension|`scenarios/emulation/`, `scenarios/real\_samples/`|Expanded malicious class; generalization results reported|

\---

## 7\. Dependencies

**Python:** `xgboost`, `scikit-learn`, `torch`, `pandas`, `numpy`, `pyarrow`, `python-evtx`, `shap`, `pyyaml`, `networkx`, `matplotlib`, `seaborn`, `pytest`

**Guest system:** Windows 10/11, Sysmon, Invoke-AtomicRedTeam, MITRE Caldera agent

**Host system:** Oracle VirtualBox with `VBoxManage`, Python 3.11+

\---

## 8\. References

\[15] Pendlebury F. et al. TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time. USENIX Security, 2019.
\[16] Arp D. et al. Dos and Don'ts of Machine Learning in Computer Security. USENIX Security, 2022.
\[17] Lundberg S. M., Lee S.-I. A Unified Approach to Interpreting Model Predictions. NeurIPS, 2017.

