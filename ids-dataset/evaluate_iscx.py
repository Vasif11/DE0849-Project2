#!/usr/bin/env python3
"""IDS evaluation on the ISCXIDS2012 subset (Phase: independent dataset evaluation).

Supervised Random Forest intrusion detection on labelled flow features. Reports a confusion matrix
and precision / recall (detection rate) / F1 / false-positive rate, overall and per attack scenario,
and discusses class imbalance and limitations. Does NOT rely on accuracy alone.

Reads   ids-dataset/data/iscx_flows.csv   (from parse_iscx.py)
Writes  ids-dataset/results/*.md, *.json, figures/*.png
"""
import json
import os

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.environ.get("ISCX_CSV", os.path.join(HERE, "data", "iscx_flows.csv"))
RES = os.path.join(HERE, "results")
FIG = os.path.join(HERE, "figures")
os.makedirs(RES, exist_ok=True)
os.makedirs(FIG, exist_ok=True)

NUM = ["sourcePort", "destinationPort", "totalSourceBytes", "totalDestinationBytes",
       "totalSourcePackets", "totalDestinationPackets", "duration_s"]
CAT = ["protocolName", "direction", "appName"]


def main():
    df = pd.read_csv(CSV)
    df["label"] = (df["tag"].str.lower() == "attack").astype(int)
    for c in NUM:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    # derived features
    df["total_bytes"] = df["totalSourceBytes"] + df["totalDestinationBytes"]
    df["total_packets"] = df["totalSourcePackets"] + df["totalDestinationPackets"]
    df["bytes_ratio"] = df["totalSourceBytes"] / (df["totalDestinationBytes"] + 1)
    num = NUM + ["total_bytes", "total_packets", "bytes_ratio"]
    # categorical -> codes (top categories kept; rare folded into 'other')
    cat_cols = []
    for c in CAT:
        top = df[c].value_counts().nlargest(25).index
        col = c + "_code"
        df[col] = pd.Series(np.where(df[c].isin(top), df[c], "other"),
                            index=df.index).astype("category").cat.codes
        cat_cols.append(col)
    features = num + cat_cols

    X = df[features].values
    y = df["label"].values
    scen = df["scenario"].values
    cat_label = df["category"].values

    X_tr, X_te, y_tr, y_te, sc_tr, sc_te, cl_tr, cl_te = train_test_split(
        X, y, scen, cat_label, test_size=0.30, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=120, max_depth=18, n_jobs=-1,
                                 class_weight="balanced", random_state=42)
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)

    tn, fp, fn, tp = confusion_matrix(y_te, y_pred, labels=[0, 1]).ravel()
    precision = precision_score(y_te, y_pred, zero_division=0)
    recall = recall_score(y_te, y_pred, zero_division=0)      # detection rate
    f1 = f1_score(y_te, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(y_te)

    # per-category detection (recall among the attack flows of each scenario)
    per_cat = {}
    for cat in sorted(set(cl_te[y_te == 1])):
        mask = (y_te == 1) & (cl_te == cat)
        if mask.sum():
            per_cat[cat] = {"attack_flows_in_test": int(mask.sum()),
                            "detected": int((y_pred[mask] == 1).sum()),
                            "detection_rate": round(float((y_pred[mask] == 1).mean()), 4)}
    # normal classification (how normal traffic was handled)
    normal_mask = y_te == 0
    normal_correct = int((y_pred[normal_mask] == 0).sum())

    imbalance = {"total_flows": int(len(df)),
                 "normal": int((y == 0).sum()), "attack": int((y == 1).sum()),
                 "attack_fraction": round(float((y == 1).mean()), 4)}

    results = {
        "dataset": "ISCXIDS2012 (labeled_flows_xml subset)",
        "scenarios": {s: int((df["scenario"] == s).sum()) for s in sorted(df["scenario"].unique())},
        "attack_categories": {c: int((df["category"] == c).sum()) for c in sorted(df["category"].unique())},
        "method": "RandomForest (supervised), 70/30 stratified split, class_weight=balanced",
        "features": features,
        "class_imbalance": imbalance,
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
        "metrics": {"precision": round(precision, 4), "recall_detection_rate": round(recall, 4),
                    "f1": round(f1, 4), "false_positive_rate": round(fpr, 4),
                    "accuracy": round(accuracy, 4)},
        "per_scenario_detection": per_cat,
        "normal_traffic": {"test_normal_flows": int(normal_mask.sum()),
                           "classified_normal": normal_correct,
                           "misclassified_as_attack": int(normal_mask.sum()) - normal_correct},
    }
    with open(os.path.join(RES, "iscx-evaluation.json"), "w") as f:
        json.dump(results, f, indent=2)

    # ---- confusion matrix figure
    cm = np.array([[tn, fp], [fn, tp]])
    fig, ax = plt.subplots(figsize=(4.6, 4.2))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1], ["pred Normal", "pred Attack"])
    ax.set_yticks([0, 1], ["Normal", "Attack"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=11)
    ax.set_title("ISCXIDS2012 - RandomForest confusion matrix")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "confusion_matrix.png"), dpi=140)
    plt.close(fig)

    # ---- feature importance figure
    imp = sorted(zip(features, clf.feature_importances_), key=lambda x: x[1], reverse=True)[:12]
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.barh([k for k, _ in imp][::-1], [v for _, v in imp][::-1], color="#2a78d6")
    ax.set_title("Top feature importances (RandomForest)")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "feature_importance.png"), dpi=140)
    plt.close(fig)

    # ---- markdown report
    md = [
        "# ISCXIDS2012 - IDS Evaluation",
        "",
        f"**Dataset subset:** {results['dataset']}",
        "",
        "## Selected files / scenarios",
        "",
        "| Scenario (day) | Flows | Attack category |",
        "|---|---:|---|",
    ]
    cat_by_scen = df[df.label == 1].groupby("scenario")["category"].agg(lambda s: s.mode().iat[0] if len(s) else "-")
    for s, cnt in results["scenarios"].items():
        md.append(f"| {s} | {cnt:,} | {cat_by_scen.get(s, 'Normal only')} |")
    md += [
        "",
        f"**Class imbalance:** {imbalance['normal']:,} normal vs {imbalance['attack']:,} attack "
        f"({imbalance['attack_fraction']*100:.2f}% attack).",
        "",
        "## Method",
        "",
        f"{results['method']}. Features: " + ", ".join(features) + ".",
        "",
        "## Confusion matrix (test set)",
        "",
        "| | pred Normal | pred Attack |",
        "|---|---:|---:|",
        f"| **Normal** | {tn:,} (TN) | {fp:,} (FP) |",
        f"| **Attack** | {fn:,} (FN) | {tp:,} (TP) |",
        "",
        "## Detection metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Precision | {precision:.4f} |",
        f"| Recall / detection rate | {recall:.4f} |",
        f"| F1-score | {f1:.4f} |",
        f"| False-positive rate | {fpr:.4f} |",
        f"| Accuracy (not relied on alone) | {accuracy:.4f} |",
        "",
        "## Per-scenario detection (attack flows only)",
        "",
        "| Attack category | Attack flows (test) | Detected | Detection rate |",
        "|---|---:|---:|---:|",
    ]
    for cat, d in per_cat.items():
        md.append(f"| {cat} | {d['attack_flows_in_test']:,} | {d['detected']:,} | {d['detection_rate']:.4f} |")
    md += [
        "",
        f"Normal traffic: {normal_correct:,} of {int(normal_mask.sum()):,} test normal flows classified "
        f"as normal ({results['normal_traffic']['misclassified_as_attack']:,} false alarms).",
        "",
        "![confusion matrix](../figures/confusion_matrix.png)",
        "![feature importance](../figures/feature_importance.png)",
        "",
        "## Discussion: class imbalance, limitations, benchmark vs real telecom",
        "",
        "- **Class imbalance:** attacks are a small minority of flows, so overall accuracy is "
        "misleading; precision/recall/FPR and per-scenario detection are the meaningful measures. "
        "`class_weight=balanced` compensates during training.",
        "- **Dataset limitations:** ISCXIDS2012 is a 2010 benchmark captured in a controlled testbed. "
        "Flow durations are coarse (aggregated) and some attacks are very underrepresented in a single "
        "day-file, which inflates variance of their detection rate.",
        "- **Detection-method limitations:** a supervised model learns the labels of THIS dataset and "
        "does not generalise to unseen attack types; it is an offline evaluation, not an inline IDS.",
        "- **Benchmark vs real-world telecom security:** high scores here do not transfer to a live 5G "
        "network, where traffic mixes, encryption, encapsulation (GTP-U) and novel attacks differ. The "
        "value of the exercise is the methodology (labelled evaluation, confusion matrix, per-class "
        "detection), not the absolute numbers.",
    ]
    with open(os.path.join(RES, "iscx-evaluation.md"), "w") as f:
        f.write("\n".join(md) + "\n")

    print(f"precision={precision:.4f} recall={recall:.4f} f1={f1:.4f} fpr={fpr:.4f} "
          f"TP={tp} FP={fp} FN={fn} TN={tn}")
    for cat, d in per_cat.items():
        print(f"  {cat}: detection_rate={d['detection_rate']:.4f} ({d['detected']}/{d['attack_flows_in_test']})")


if __name__ == "__main__":
    main()
