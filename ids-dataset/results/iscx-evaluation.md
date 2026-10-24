# ISCXIDS2012 - IDS Evaluation

**Dataset subset:** ISCXIDS2012 (labeled_flows_xml subset)

## Selected files / scenarios

| Scenario (day) | Flows | Attack category |
|---|---:|---|
| SatJun12 | 133,193 | Infiltration |
| SunJun13 | 275,528 | HTTP_DoS |
| ThuJun17 | 61,832 | BruteForce_SSH |

**Class imbalance:** 447,912 normal vs 22,641 attack (4.81% attack).

## Method

RandomForest (supervised), 70/30 stratified split, class_weight=balanced. Features: sourcePort, destinationPort, totalSourceBytes, totalDestinationBytes, totalSourcePackets, totalDestinationPackets, duration_s, total_bytes, total_packets, bytes_ratio, protocolName_code, direction_code, appName_code.

## Confusion matrix (test set)

| | pred Normal | pred Attack |
|---|---:|---:|
| **Normal** | 134,365 (TN) | 9 (FP) |
| **Attack** | 22 (FN) | 6,770 (TP) |

## Detection metrics

| Metric | Value |
|---|---:|
| Precision | 0.9987 |
| Recall / detection rate | 0.9968 |
| F1-score | 0.9977 |
| False-positive rate | 0.0001 |
| Accuracy (not relied on alone) | 0.9998 |

## Per-scenario detection (attack flows only)

| Attack category | Attack flows (test) | Detected | Detection rate |
|---|---:|---:|---:|
| BruteForce_SSH | 61 | 60 | 0.9836 |
| HTTP_DoS | 6,096 | 6,075 | 0.9966 |
| Infiltration | 635 | 635 | 1.0000 |

Normal traffic: 134,365 of 134,374 test normal flows classified as normal (9 false alarms).

![confusion matrix](../figures/confusion_matrix.png)
![feature importance](../figures/feature_importance.png)

## Discussion: class imbalance, limitations, benchmark vs real telecom

- **Class imbalance:** attacks are a small minority of flows, so overall accuracy is misleading; precision/recall/FPR and per-scenario detection are the meaningful measures. `class_weight=balanced` compensates during training.
- **Dataset limitations:** ISCXIDS2012 is a 2010 benchmark captured in a controlled testbed. Flow durations are coarse (aggregated) and some attacks are very underrepresented in a single day-file, which inflates variance of their detection rate.
- **Detection-method limitations:** a supervised model learns the labels of THIS dataset and does not generalise to unseen attack types; it is an offline evaluation, not an inline IDS.
- **Benchmark vs real-world telecom security:** high scores here do not transfer to a live 5G network, where traffic mixes, encryption, encapsulation (GTP-U) and novel attacks differ. The value of the exercise is the methodology (labelled evaluation, confusion matrix, per-class detection), not the absolute numbers.
