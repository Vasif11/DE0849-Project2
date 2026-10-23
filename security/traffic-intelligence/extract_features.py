#!/usr/bin/env python3
"""Scenario B Phase 2C-Advanced - bounded traffic intelligence on the controlled PCAP.

Transforms the current-run PCAP into per-HTTP-request features and applies a lightweight anomaly
detector (IsolationForest with a statistical fallback). The controlled SQLi request is expected to
be flagged as anomalous relative to the normal Juice Shop traffic. Results are SUPPLEMENTARY
evidence, correlated with the deterministic ZAP/Suricata results, not a stand-alone IDS.

Outputs:
  security/traffic-intelligence/traffic-features.csv
  security/traffic-intelligence/traffic-anomaly.json
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
PCAP = os.environ.get("PCAP", os.path.join(ROOT, "security", "traffic", "scenario-b", "ci", "juice-shop-ci-sqli.pcapng"))
FEATURES_CSV = os.path.join(HERE, "traffic-features.csv")
ANOMALY_JSON = os.path.join(HERE, "traffic-anomaly.json")

SQLI_META = ["%27", "%28", "%29", "'", "(", ")", "--", " or ", "%20or%20", "union", "select"]


def extract_requests(pcap):
    cmd = ["tshark", "-r", pcap, "-Y", "http.request", "-T", "fields", "-E", "separator=\t",
           "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport",
           "-e", "http.request.method", "-e", "http.request.uri", "-e", "frame.len"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        t, src, dst, dport, method, uri, flen = parts[:7]
        if not uri:
            continue
        rows.append({"time": float(t or 0), "src": src, "dst": dst, "dport": dport,
                     "method": method, "uri": uri, "frame_len": int(flen or 0)})
    return rows


def featurize(rows):
    feats = []
    for r in rows:
        uri = r["uri"].lower()
        special = sum(uri.count(c) for c in ["%", "'", "(", ")", "=", "-", ";", "&"])
        sqli_hits = sum(1 for m in SQLI_META if m in uri)
        feats.append({
            **r,
            "uri_len": len(r["uri"]),
            "special_chars": special,
            "digit_count": sum(ch.isdigit() for ch in r["uri"]),
            "has_query": int("?" in r["uri"]),
            "sqli_token_hits": sqli_hits,
            "is_encoded_quote_paren": int("%27%28" in r["uri"] or "%27%29" in r["uri"]),
        })
    return feats


def detect(feats):
    import math
    X = [[f["uri_len"], f["special_chars"], f["sqli_token_hits"], f["digit_count"]] for f in feats]
    method = "none"
    scores = [0.0] * len(feats)
    flags = [False] * len(feats)
    if len(feats) >= 8:
        try:
            from sklearn.ensemble import IsolationForest
            clf = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            pred = clf.fit_predict(X)                 # -1 = anomaly
            sc = clf.score_samples(X)
            scores = [float(-s) for s in sc]          # higher = more anomalous
            flags = [p == -1 for p in pred]
            method = "IsolationForest"
        except Exception as e:
            print(f"[ti] sklearn unavailable ({e}); using statistical z-score fallback")
    if method == "none":
        # statistical fallback: z-score on special_chars + sqli_token_hits
        vals = [f["special_chars"] + 3 * f["sqli_token_hits"] for f in feats]
        mu = sum(vals) / len(vals) if vals else 0
        var = sum((v - mu) ** 2 for v in vals) / len(vals) if vals else 0
        sd = math.sqrt(var) or 1.0
        scores = [(v - mu) / sd for v in vals]
        flags = [s >= 2.0 for s in scores]
        method = "zscore"
    # the encoded quote/paren signature is always treated as anomalous (rule-assisted)
    for i, f in enumerate(feats):
        if f["is_encoded_quote_paren"] or f["sqli_token_hits"] >= 2:
            flags[i] = True
    return method, scores, flags


def main():
    if not os.path.exists(PCAP):
        print(f"[ti] PCAP not found: {PCAP}", file=sys.stderr)
        sys.exit(2)
    rows = extract_requests(PCAP)
    feats = featurize(rows)
    if not feats:
        print("[ti] no HTTP requests found in PCAP", file=sys.stderr)
        sys.exit(2)
    method, scores, flags = detect(feats)

    cols = ["time", "src", "dst", "dport", "method", "uri", "frame_len", "uri_len",
            "special_chars", "digit_count", "has_query", "sqli_token_hits",
            "is_encoded_quote_paren", "anomaly_score", "anomaly"]
    with open(FEATURES_CSV, "w") as f:
        f.write(",".join(cols) + "\n")
        for r, s, fl in zip(feats, scores, flags):
            r = dict(r)
            r["uri"] = '"' + r["uri"].replace('"', "'") + '"'
            r["anomaly_score"] = round(s, 4)
            r["anomaly"] = int(fl)
            f.write(",".join(str(r[c]) for c in cols) + "\n")

    anomalies = [{"time": r["time"], "src": r["src"], "method": r["method"], "uri": r["uri"],
                  "sqli_token_hits": r["sqli_token_hits"], "anomaly_score": round(s, 4)}
                 for r, s, fl in zip(feats, scores, flags) if fl]
    sqli_flagged = any(r["is_encoded_quote_paren"] for r, fl in zip(feats, flags) if fl)
    out = {
        "run_id": os.environ.get("RUN_ID"),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "pcap": os.path.relpath(PCAP, ROOT),
        "method": method,
        "total_http_requests": len(feats),
        "anomalies_detected": len(anomalies),
        "controlled_sqli_flagged": bool(sqli_flagged),
        "note": "Supplementary analytics on bounded controlled traffic; not production detection accuracy.",
        "anomalies": anomalies[:20],
    }
    with open(ANOMALY_JSON, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[ti] method={method} requests={len(feats)} anomalies={len(anomalies)} "
          f"controlled_sqli_flagged={sqli_flagged}")


if __name__ == "__main__":
    main()
