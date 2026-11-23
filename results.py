from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import shutil
from pathlib import Path

import numpy as np
import pandas as pd

from collector import load_config

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
TEXT, TEXT2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#ffffff"
TTD_NAME = {"simulator": "Behavioural simulators", "atomic": "Atomic Red Team",
            "sample": "Real samples (all families)"}
STAGE_ORDER = ["gbm", "lstm", "anomaly", "fused"]
STAGE_NAME = {"gbm": "Stage 1: XGBoost", "lstm": "Stage 2: LSTM",
              "anomaly": "Isolation Forest", "fused_no_tree": "Fusion (no tree aggregation)",
              "fused": "Fusion + process tree"}
SOURCE_NAME = {"simulator": "Behavioural simulators", "atomic": "Atomic Red Team",
               "sample": "Real samples (seen families)",
               "sample_unseen_family": "Real samples (unseen families)"}

FEATURE_GROUPS = {
    "Static attributes": ["image_is_lolbin", "image_is_shell", "n_img_load", "n_unsigned_load"],
    "Launch context": ["cmdline_len", "cmdline_entropy", "cmdline_n_args", "parent_is_shell",
                       "parent_is_office", "parent_is_lolbin", "integrity_rank", "depth"],
    "Resource metrics and activity intensity": ["cpu_max_pct", "cpu_mean_pct", "cpu_total_s", "ws_max_mb",
                                                "ws_growth_mb", "private_max_mb", "threads_max",
                                                "threads_growth", "handles_max", "res_samples", "n_events",
                                                "event_rate", "terminated_in_window", "lifetime_in_window_s"],
    "File and registry activity": ["n_file_create", "n_exec_file_create", "n_unique_file_ext",
                                   "n_file_delete", "n_autorun_writes", "n_reg_set", "n_reg_key_op"],
    "Network activity": ["n_net", "n_unique_ip", "n_unique_port", "n_dns", "n_unique_domain"],
    "Inter-process interaction": ["n_children", "remote_thread_out", "process_access_out",
                                  "n_high_access_out", "n_access_targets", "lsass_access",
                                  "is_injected"],
}


def plt_setup():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": GRID, "axes.labelcolor": TEXT2, "xtick.color": TEXT2, "ytick.color": TEXT2,
        "text.color": TEXT, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
        "axes.spines.top": False, "axes.spines.right": False, "font.size": 10,
        "axes.titlesize": 11, "axes.titleweight": "bold", "legend.frameon": False,
        "lines.linewidth": 2, "figure.dpi": 150,
    })
    return plt


def save(fig, path: Path):
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    import matplotlib.pyplot as plt
    plt.close(fig)


def metrics_tables(rep: dict, tdir: Path):
    rows = []
    for part in ("overall_test", "overall_val"):
        for stage, m in rep[part].items():
            rows.append({"split": part.split("_")[1], "stage": stage, "stage_name": STAGE_NAME.get(stage, stage), **m})
    pd.DataFrame(rows).to_csv(tdir / "metrics_overall.csv", index=False)
    for key, fname, col in (("by_source_test", "metrics_by_source.csv", "source"),
                            ("by_scenario_test", "metrics_by_scenario.csv", "scenario"),
                            ("by_family_test", "metrics_by_family.csv", "family")):
        rows = [{col: g, "stage": s, **m} for g, stages in rep.get(key, {}).items() for s, m in stages.items()]
        pd.DataFrame(rows).to_csv(tdir / fname, index=False)
    pd.DataFrame([{"stage": k, "threshold": v} for k, v in rep["thresholds_from_validation"].items()]) \
        .to_csv(tdir / "thresholds.csv", index=False)


def dataset_tables(cfg: dict, tdir: Path) -> pd.DataFrame:
    raw = Path(cfg["paths"]["raw"])
    ev = pd.read_parquet(cfg["paths"]["events"], columns=["run_id", "event_id", "process_guid", "label"])
    per_run = ev.groupby("run_id").agg(n_events=("event_id", "size"),
                                       n_processes=("process_guid", "nunique"))
    mal = ev[ev["label"] == 1].groupby("run_id").agg(n_malicious_events=("event_id", "size"),
                                                    n_malicious_processes=("process_guid", "nunique"))
    split = pd.read_csv(Path(cfg["paths"]["reports"]) / cfg["_feature_set"] / "runs_split.csv")[["run_id", "split"]]
    rows = []
    for mp in sorted(raw.glob("*/meta.json")):
        m = json.loads(mp.read_text(encoding="utf-8"))
        out = m.get("scenario_output") or ""
        exit_line = [ln for ln in out.splitlines() if "exit code after" in ln]
        rows.append({"run_id": m["run_id"], "scenario": m["scenario"], "kind": m["kind"],
                     "run_label": m["label"], "attack": m.get("attack"), "technique": m.get("technique"),
                     "family": m.get("family"), "sha256": m.get("sha256"),
                     "scenario_start_utc": m.get("scenario_start_utc"),
                     "duration_s": m.get("duration_s"), "seed_resolved": bool(m.get("seed_guid")),
                     "sink_records": m.get("sink_records"),
                     "sample_exit_code": exit_line[0].split(":")[-1].strip() if exit_line else None,
                     "has_resources": (mp.parent / "resources.csv").exists()})
    runs = pd.DataFrame(rows).merge(per_run, on="run_id", how="left").merge(mal, on="run_id", how="left") \
        .merge(split, on="run_id", how="left")
    runs[["n_malicious_events", "n_malicious_processes"]] = runs[["n_malicious_events", "n_malicious_processes"]].fillna(0).astype(int)
    runs.to_csv(tdir / "dataset_runs.csv", index=False)

    summ = runs.groupby(["kind", "scenario"]).agg(
        runs=("run_id", "size"), seed_resolved=("seed_resolved", "sum"),
        events=("n_events", "sum"), processes=("n_processes", "sum"),
        malicious_processes=("n_malicious_processes", "sum")).reset_index()
    summ.to_csv(tdir / "dataset_by_scenario.csv", index=False)

    f = pd.read_parquet(cfg["paths"]["features"], columns=["run_id", "label"]).merge(split, on="run_id")
    f = f.merge(runs[["run_id", "kind"]], on="run_id")
    split_summ = f.groupby(["split", "kind"]).agg(processes=("label", "size"),
                                                  malicious_processes=("label", "sum")).reset_index()
    split_summ.to_csv(tdir / "dataset_by_split.csv", index=False)

    man = pd.read_csv(Path(cfg["samples"]["dir"]) / "manifest.csv")
    s = runs[runs["kind"] == "sample"][["sha256", "run_id", "split", "seed_resolved", "n_malicious_processes",
                                         "n_malicious_events", "sink_records", "sample_exit_code"]]
    samples = man.drop(columns=["archive"], errors="ignore").merge(s, on="sha256", how="left")
    samples["holdout_family"] = samples["family"].isin(cfg["samples"].get("holdout_families") or [])
    samples["observed_behaviour"] = np.select(
        [samples["run_id"].isna(), samples["n_malicious_processes"].fillna(0) <= 1],
        ["excluded_log_flood", "not_executed"], "executed")
    samples.to_csv(tdir / "samples.csv", index=False)

    feat_rows = [{"feature": c, "group": g} for g, cols in FEATURE_GROUPS.items() for c in cols]
    pd.DataFrame(feat_rows).to_csv(tdir / "feature_list.csv", index=False)
    return runs


def fig_roc_pr(pred: pd.DataFrame, rep: dict, fdir: Path):
    from sklearn.metrics import precision_recall_curve, roc_curve
    plt = plt_setup()
    te = pred[pred["split"] == "test"]
    y = te["label"].to_numpy()
    if len(set(y)) < 2:
        return
    plt.rcParams.update({"font.size": 13, "axes.titlesize": 13})
    fig, axes = plt.subplots(1, 2, figsize=(10, 5.2))
    for i, st in enumerate(STAGE_ORDER):
        m = rep["overall_test"][st]
        fpr, tpr, _ = roc_curve(y, te[st])
        ls = ["-", "--", "-.", "-"][i]
        lw = 3.2 if st == "fused" else 2.0
        axes[0].plot(fpr, tpr, color=SERIES[i], ls=ls, lw=lw,
                     label=f"{STAGE_NAME[st]} (ROC-AUC {m['roc_auc']:.3f}, AP {m['pr_auc']:.3f})")
        p, r, _ = precision_recall_curve(y, te[st])
        axes[1].plot(r, p, color=SERIES[i], ls=ls, lw=lw)
    axes[0].set_xscale("log"); axes[0].set_xlim(1e-4, 1)
    axes[0].axvline(rep["target_fpr"], color=TEXT2, lw=1, ls="--")
    axes[0].text(rep["target_fpr"] * 1.15, 0.75, f"target FPR\n{rep['target_fpr']:g}", color=TEXT2, fontsize=11)
    axes[0].set(title="ROC curve (log FPR)", xlabel="False positive rate", ylabel="True positive rate")
    axes[1].set(title="Precision-recall curve", xlabel="Recall", ylabel="Precision")
    for ax in axes:
        ax.set_ylim(0, 1.02)
    fig.legend(*axes[0].get_legend_handles_labels(), loc="lower center", ncol=2, fontsize=11,
               bbox_to_anchor=(0.5, 0.0))
    fig.tight_layout(rect=(0, 0.16, 1, 1))
    fig.savefig(fdir / "roc_pr_curves.png", dpi=200)
    plt.close(fig)


def fig_scores(pred: pd.DataFrame, rep: dict, fdir: Path):
    plt = plt_setup()
    plt.rcParams.update({"font.size": 13, "axes.titlesize": 13})
    te = pred[pred["split"] == "test"]
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.4), sharey=True)
    for ax, st in zip(axes, ("gbm", "fused")):
        bins = np.linspace(0, 1, 41)
        ax.hist(te.loc[te.label == 0, st], bins=bins, color=SERIES[0], alpha=0.85, label="Benign processes",
                edgecolor=SURFACE, linewidth=0.5)
        ax.hist(te.loc[te.label == 1, st], bins=bins, color=SERIES[1], alpha=0.85, label="Malicious processes",
                edgecolor=SURFACE, linewidth=0.5)
        thr = rep["thresholds_from_validation"][st]
        ax.axvline(thr, color=TEXT, lw=1, ls="--")
        ax.text(thr, 300, f" threshold {thr:.3f}", fontsize=11,
                color=TEXT2, va="top")
        ax.set_yscale("log")
        ax.set(title=STAGE_NAME[st], xlabel="Score", ylabel="Processes (log)")
        ax.legend(fontsize=11, loc="center right", bbox_to_anchor=(0.9, 0.45))
    axes[1].tick_params(labelleft=True)
    save(fig, fdir / "score_distributions.png")


def fig_confusion(rep: dict, fdir: Path):
    plt = plt_setup()
    stages = STAGE_ORDER
    plt.rcParams.update({"font.size": 12, "axes.titlesize": 12})
    fig, axes = plt.subplots(2, 2, figsize=(8, 7.4))
    for ax, st in zip(axes.ravel(), stages):
        m = rep["overall_test"][st]
        mat = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
        norm = mat / np.maximum(mat.sum(axis=1, keepdims=True), 1)
        ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
        for (i, j), v in np.ndenumerate(mat):
            ax.text(j, i, f"{v}\n({norm[i, j]:.1%})", ha="center", va="center", fontsize=13,
                    color=SURFACE if norm[i, j] > 0.55 else TEXT)
        ax.set_xticks([0, 1], ["Benign", "Malicious"]); ax.set_yticks([0, 1], ["Benign", "Malicious"])
        ax.set(xlabel="Predicted", ylabel="Actual", title=STAGE_NAME[st])
        ax.grid(False)
    fig.suptitle("Confusion matrices on the test set (validation-calibrated thresholds)", fontsize=12)
    save(fig, fdir / "confusion_matrices.png")


def fig_by_group(rep: dict, key: str, label: dict | None, title: str, fname: str, fdir: Path):
    data = rep.get(key, {})
    if not data:
        return
    plt = plt_setup()
    groups = list(data.keys())
    names = [(label or {}).get(g, g) for g in groups]
    rec = [data[g]["fused"]["recall"] for g in groups]
    roc = [data[g]["fused"]["roc_auc"] for g in groups]
    order = np.argsort(rec)
    fig, ax = plt.subplots(figsize=(8, 0.42 * len(groups) + 1.4))
    yy = np.arange(len(groups))
    ax.barh(yy, np.array(rec)[order], color=SERIES[0], height=0.62)
    for k, i in enumerate(order):
        npos = data[groups[i]]["fused"]["n_pos"]
        ax.text(rec[i] + 0.01, k, f"{rec[i]:.2f}  (n={npos}, ROC-AUC {roc[i]:.3f})", va="center",
                fontsize=8, color=TEXT2)
    ax.set_yticks(yy, np.array(names)[order]); ax.set_xlim(0, 1.45)
    ax.set(xlabel="Recall of malicious processes (fusion + tree, validation threshold)", title=title)
    ax.grid(axis="y", visible=False)
    save(fig, fdir / fname)


def fig_shap(rdir: Path, fdir: Path, tdir: Path):
    plt = plt_setup()
    import shap
    z = np.load(rdir / "shap_values.npz", allow_pickle=True)
    imp = pd.read_csv(rdir / "shap_importance.csv")
    imp.to_csv(tdir / "shap_importance.csv", index=False)
    shap.summary_plot(z["values"], z["X"], feature_names=list(z["features"]), show=False,
                      max_display=15, plot_size=(8, 6))
    fig = plt.gcf(); fig.suptitle("SHAP values, Stage 1 (XGBoost), test set", fontsize=10)
    save(fig, fdir / "shap_summary.png")
    top = imp.head(15).iloc[::-1]
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.barh(top["feature"], top["mean_abs_shap"], color=SERIES[0], height=0.62)
    ax.set(xlabel="Mean |SHAP value|", title="Top-15 features by mean |SHAP| (Stage 1)")
    ax.grid(axis="y", visible=False)
    save(fig, fdir / "shap_top_features.png")


def fig_ttd(rdir: Path, fdir: Path, tdir: Path):
    ttd = pd.read_csv(rdir / "time_to_detection.csv")
    ttd.to_csv(tdir / "time_to_detection.csv", index=False)
    summ = ttd.groupby("kind").agg(runs=("run_id", "size"), detected=("detected", "sum"),
                                   median_ttd_s=("ttd_s", "median")).reset_index()
    summ.to_csv(tdir / "time_to_detection_summary.csv", index=False)
    plt = plt_setup()
    plt.rcParams.update({"font.size": 12, "axes.titlesize": 12})
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for i, (kind, g) in enumerate(ttd.groupby("kind")):
        t = np.sort(g["ttd_s"].dropna().to_numpy())
        if not len(t):
            continue
        frac = np.arange(1, len(t) + 1) / len(g)
        ax.step(np.r_[9.8, t, 11.0], np.r_[0, frac, frac[-1]], where="post", color=SERIES[i],
                lw=2.4 - 0.4 * i, label=f"{TTD_NAME.get(kind, kind)} ({len(t)}/{len(g)} runs)")
    ax.axvline(10, color=TEXT2, lw=1, ls="--")
    ax.text(10.03, 0.45, "shortest window (10 s):\nearliest possible detection", ha="left", fontsize=10,
            color=TEXT2)
    ax.set(xlabel="Seconds from scenario start", ylabel="Cumulative share of runs detected",
           title="Cumulative share of malicious runs detected", ylim=(0, 1.05), xlim=(9.8, 11.0))
    ax.set_xticks(np.arange(9.8, 11.01, 0.2))
    ax.legend(fontsize=10, loc="lower right")
    save(fig, fdir / "time_to_detection.png")


def fig_dataset(cfg: dict, runs: pd.DataFrame, fdir: Path):
    plt = plt_setup()
    f = pd.read_parquet(cfg["paths"]["features"], columns=["run_id", "label"]) \
        .merge(runs[["run_id", "scenario", "kind"]], on="run_id")
    g = f.groupby(["kind", "scenario"])["label"].agg(malicious="sum", total="size").reset_index()
    g["benign"] = g["total"] - g["malicious"]
    g = g.sort_values(["kind", "scenario"], ascending=False)
    plt.rcParams.update({"font.size": 11, "axes.titlesize": 12})
    fig, ax = plt.subplots(figsize=(9, 0.33 * len(g) + 1.4))
    yy = np.arange(len(g))
    h = 0.36
    ax.barh(yy + h / 2 + 0.01, g["benign"], height=h, color=SERIES[0], label="Benign processes")
    ax.barh(yy - h / 2 - 0.01, g["malicious"], height=h, color=SERIES[1], label="Malicious processes")
    for y, b, m in zip(yy, g["benign"], g["malicious"]):
        ax.text(max(b, 1) * 1.08, y + h / 2, f"{b:,}", va="center", fontsize=9, color=TEXT2)
        if m:
            ax.text(m * 1.08, y - h / 2, f"{m:,}", va="center", fontsize=9, color=TEXT2)
    ax.set_yticks(yy, [f"{s} ({k})" for s, k in zip(g["scenario"], g["kind"])])
    ax.set_xscale("log")
    ax.set_xlim(0.8, max(g["benign"].max(), 1) * 3)
    ax.set_xlabel("Processes (log scale)"); ax.set_title("Dataset composition by scenario")
    ax.legend(fontsize=10, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2)
    ax.grid(axis="y", visible=False)
    save(fig, fdir / "dataset_composition.png")


def fig_lstm_loss(rep: dict, fdir: Path):
    hist = rep.get("lstm_train_loss") or []
    if not hist:
        return
    plt = plt_setup()
    fig, ax = plt.subplots(figsize=(5.5, 3.4))
    ax.plot(np.arange(1, len(hist) + 1), hist, color=SERIES[0], marker="o", markersize=4)
    ax.set(xlabel="Epoch", ylabel="Weighted BCE loss", title="Stage 2 (LSTM) training loss")
    save(fig, fdir / "lstm_training_loss.png")


def ablation_table(cfg: dict, tdir: Path, fdir: Path):
    rows = []
    for name, excl in (cfg["models"].get("feature_sets") or {}).items():
        mp = Path(cfg["paths"]["reports"]) / name / "metrics.json"
        if not mp.exists():
            continue
        rep = json.loads(mp.read_text())
        for stage, m in rep["overall_test"].items():
            rows.append({"feature_set": name, "excluded_features": ";".join(excl or []),
                         "n_features": rep.get("n_features"), "scope": "overall", "stage": stage, **m})
        for src, stages in rep.get("by_source_test", {}).items():
            rows.append({"feature_set": name, "excluded_features": ";".join(excl or []),
                         "n_features": rep.get("n_features"), "scope": src, "stage": "fused",
                         **stages["fused"]})
    pd.DataFrame(rows).to_csv(tdir / "metrics_ablation.csv", index=False)


def write_readme(cfg: dict, rep: dict, runs: pd.DataFrame, out: Path):
    import sklearn, xgboost, torch, shap as shap_mod
    o = rep["overall_test"]["fused"]
    lines = [
        "# Results package",
        "",
        "Generated by `python results.py` on "
        f"{dt.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}. All numbers come from the files in this folder;",
        "nothing is typed in by hand. Text, tables and figures are in English.",
        "",
        "## Headline (test set, fusion + process-tree aggregation)",
        "",
        f"| Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC | Recall @ FPR <= {rep['target_fpr']:g} |",
        "|---|---|---|---|---|---|---|",
        f"| {o['precision']:.3f} | {o['recall']:.3f} | {o['f1']:.3f} | {o['fpr']:.4f} | {o['roc_auc']:.3f} | "
        f"{o['pr_auc']:.3f} | {o['recall_at_target_fpr']:.3f} |",
        "",
        "## Experimental setup",
        "",
        f"- Runs: {len(runs)} ({runs['kind'].value_counts().to_dict()}); split train/val/test = "
        f"{rep['runs']['train']}/{rep['runs']['val']}/{rep['runs']['test']} runs, "
        f"{rep['processes']['train']}/{rep['processes']['val']}/{rep['processes']['test']} processes.",
        "- Split: by run, in time order (earliest 70% of runs -> train, last 15% of those -> validation, "
        "latest 30% -> test). Families in `holdout_families` are test-only.",
        f"- Holdout (unseen) families: {cfg['samples'].get('holdout_families') or 'none'}.",
        f"- Decision thresholds: chosen on the validation set at FPR <= {rep['target_fpr']:g}, applied unchanged to test.",
        f"- Feature window: {cfg['models']['feature_window_s']} s after process start; time to detection uses "
        f"{cfg['features']['windows_s']} s windows.",
        "- Guest: Windows 11 Pro 26300 (VirtualBox 7.2.22), Sysmon with sysmon-modular `sysmonconfig-excludes-only.xml`, "
        "Defender and UAC off, isolated internal network with a DNS/TCP sink VM (10.0.0.2).",
        "- Labels: the scenario launcher process, all its descendants and any process it injected into "
        "(CreateRemoteThread) are malicious in malicious runs; everything else is benign. In sample and "
        "Atomic runs the launcher itself only stages the payload and is excluded from the dataset "
        "(its descendants stay malicious). Only processes that start during the observation window "
        "(have a ProcessCreate event) are included.",
        "- Not used as features: image path location and file names (every real sample is launched "
        "from Downloads, no benign workload is - a collection artefact, not behaviour).",
        f"- Software: Python {platform.python_version()}, scikit-learn {sklearn.__version__}, "
        f"xgboost {xgboost.__version__}, torch {torch.__version__}, shap {shap_mod.__version__}.",
        "",
        "## Files",
        "",
        "| File | Content |",
        "|---|---|",
        "| `tables/metrics_overall.csv` | Per stage, test and validation: counts, precision, recall, F1, FPR, ROC-AUC, PR-AUC, recall at target FPR, threshold |",
        "| `tables/metrics_by_source.csv` | Same metrics per data source (positives of the source + all test benign processes) |",
        "| `tables/metrics_by_scenario.csv` | Same metrics per scenario |",
        "| `tables/metrics_by_family.csv` | Same metrics per malware family |",
        "| `tables/thresholds.csv` | Validation-calibrated thresholds per stage |",
        "| `tables/runs_test.csv` | Per test run: detected (any malicious process alerted), false alerts |",
        "| `tables/time_to_detection*.csv` | Per malicious test run detection time; summary by source |",
        "| `tables/dataset_runs.csv` | Every collected run: scenario, label, family, events, processes, seed resolution, sink records |",
        "| `tables/dataset_by_scenario.csv`, `dataset_by_split.csv` | Dataset statistics |",
        "| `tables/samples.csv` | Every real sample: family, SHA-256, first seen, observed behaviour (active / inert or evasive) |",
        "| `tables/feature_list.csv` | Features and their group (Table 1.2 of the report) |",
        "| `tables/shap_importance.csv` | Mean absolute SHAP value per feature (Stage 1) |",
        "| `figures/*.png` | Figures (see file names) |",
        "| `detect_replay/*.jsonl` | Alerts raised by `detect.py --replay` on held-out test runs |",
        "| `metrics.json`, `config.yaml` | Raw metrics and the exact configuration used |",
        "",
        "## Reproduce",
        "",
        "```",
        "python lab.py --campaign --passes 5",
        "python collector.py && python features.py && python models.py && python results.py",
        "```",
    ]
    (out / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the results package.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out", default="results")
    ap.add_argument("--feature-set", default="no_tree_context", help="primary feature set")
    args = ap.parse_args()
    cfg = load_config(args.config)
    out = Path(args.out)
    tdir, fdir = out / "tables", out / "figures"
    for d in (tdir, fdir):
        d.mkdir(parents=True, exist_ok=True)
    cfg["_feature_set"] = args.feature_set
    rdir = Path(cfg["paths"]["reports"]) / args.feature_set
    ablation_table(cfg, tdir, fdir)
    rep = json.loads((rdir / "metrics.json").read_text())
    pred = pd.read_parquet(rdir / "predictions.parquet")

    metrics_tables(rep, tdir)
    shutil.copy(rdir / "runs_test.csv", tdir / "runs_test.csv")
    runs = dataset_tables(cfg, tdir)
    fig_roc_pr(pred, rep, fdir)
    fig_scores(pred, rep, fdir)
    fig_confusion(rep, fdir)
    fig_by_group(rep, "by_source_test", SOURCE_NAME, "Recall by data source (test set)", "recall_by_source.png", fdir)
    fig_by_group(rep, "by_scenario_test", None, "Recall by scenario (test set)", "recall_by_scenario.png", fdir)
    fig_by_group(rep, "by_family_test", None, "Recall by malware family (test set)", "recall_by_family.png", fdir)
    fig_shap(rdir, fdir, tdir)
    fig_ttd(rdir, fdir, tdir)
    fig_dataset(cfg, runs, fdir)
    fig_lstm_loss(rep, fdir)
    shutil.copy(rdir / "metrics.json", out / "metrics.json")
    rep_dir = out / "detect_replay"
    if (rdir / "detect_replay").exists():
        rep_dir.mkdir(exist_ok=True)
        for f in (rdir / "detect_replay").glob("*.jsonl"):
            shutil.copy(f, rep_dir / f.name)
    shutil.copy(args.config, out / "config.yaml")
    write_readme(cfg, rep, runs, out)
    print(f"[done] results package -> {out}")


if __name__ == "__main__":
    main()
