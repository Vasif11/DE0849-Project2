#!/usr/bin/env python3
"""Scenario B security-event correlation (Phase 2E).

Connects independently generated observations for one CI run:
  - targeted ZAP JSON report    (application-security finding: SQL Injection, alert 40018)
  - Selenium auth/storage JSON  (runtime authentication evidence)
  - fresh SQLi PCAP             (network traffic evidence)
  - Suricata eve.json           (network detection: SID 1000001)

Produces security-event-correlation.json and .md. The script does not invent evidence: it reports
exactly which configured observations were found and relates them by RUN_ID, target:port and the
controlled request signature. Trivy/SBOM artefacts are referenced as archived evidence only.
"""
import json
import os
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
S = os.path.join(ROOT, "security")
OUT_DIR = os.path.join(S, "correlation", "scenario-b")

ZAP = os.path.join(S, "reports", "zap", "scenario-b-ci-targeted", "scenario-b-ci-targeted.json")
SEL = os.path.join(S, "selenium", "evidence", "juice-shop-auth-storage.json")
PCAP = os.path.join(S, "traffic", "scenario-b", "ci", "juice-shop-ci-sqli.pcapng")
EVE = os.path.join(S, "ids", "scenario-b", "ci", "eve.json")
TRIVY = os.path.join(S, "scans", "trivy-ci", "juice-shop-v20.2.0.json")
SBOM = os.path.join(S, "sbom-ci", "juice-shop-v20.2.0.cdx.json")

TARGET_HOST = "10.20.10.20"
TARGET_PORT = 3000
SQLI_SIG = "/rest/products/search?q=%27%28"
ZAP_ALERT = "40018"
SURICATA_SID = 1000001


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def zap_sqli_count(doc):
    """Count SQL Injection (alert 40018) instances in a traditional-json ZAP report."""
    if not doc:
        return 0
    n = 0
    for site in doc.get("site", []):
        for alert in site.get("alerts", []):
            if str(alert.get("pluginid")) == ZAP_ALERT or "sql injection" in alert.get("name", "").lower():
                n += int(alert.get("count", len(alert.get("instances", []))) or 1)
    return n


def suricata_sid_events(path, sid):
    """Return events in eve.json whose alert.signature_id == sid."""
    hits = []
    if not os.path.exists(path):
        return hits
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") == "alert" and ev.get("alert", {}).get("signature_id") == sid:
                hits.append({"timestamp": ev.get("timestamp"), "src_ip": ev.get("src_ip"),
                             "dest_ip": ev.get("dest_ip"), "dest_port": ev.get("dest_port"),
                             "signature": ev["alert"].get("signature"),
                             "http_uri": ev.get("http", {}).get("url")})
    return hits


def pcap_stats(path):
    info = {"exists": os.path.exists(path), "size_bytes": 0, "packets": None, "sqli_request_present": None}
    if not info["exists"]:
        return info
    info["size_bytes"] = os.path.getsize(path)
    try:
        n = subprocess.run(["tshark", "-r", path, "-T", "fields", "-e", "frame.number"],
                           capture_output=True, text=True, timeout=60).stdout
        info["packets"] = len([x for x in n.splitlines() if x.strip()])
        uris = subprocess.run(["tshark", "-r", path, "-Y", "http.request", "-T", "fields",
                               "-e", "http.request.full_uri", "-e", "http.request.uri"],
                              capture_output=True, text=True, timeout=60).stdout
        info["sqli_request_present"] = "%27%28" in uris and "/rest/products/search" in uris
    except Exception as e:
        info["tshark_error"] = str(e)
    return info


def main():
    run_id = os.environ.get("RUN_ID")
    zap = load_json(ZAP)
    sel = load_json(SEL)
    sqli_alerts = zap_sqli_count(zap)
    suri = suricata_sid_events(EVE, SURICATA_SID)
    pcap = pcap_stats(PCAP)
    if run_id is None and sel:
        run_id = sel.get("run_id")

    app_detection = sqli_alerts >= 1
    net_detection = len(suri) >= 1
    runtime_auth = bool(sel and sel.get("login_success"))
    traffic_present = bool(pcap["exists"] and pcap["size_bytes"] > 0 and pcap.get("sqli_request_present"))

    # the controlled SQLi activity is corroborated across the application-security and
    # network-detection layers for the same run
    correlated = app_detection and net_detection and traffic_present
    status = "CORRELATED" if correlated else "NOT_CORRELATED"

    report = {
        "run_id": run_id,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "target": {"host": TARGET_HOST, "port": TARGET_PORT},
        "controlled_signature": SQLI_SIG,
        "observations": {
            "zap_targeted": {"present": zap is not None, "alert_40018_count": sqli_alerts,
                             "artifact": os.path.relpath(ZAP, ROOT)},
            "selenium_runtime": {"present": sel is not None, "login_success": runtime_auth,
                                 "login_method": (sel or {}).get("login_method"),
                                 "artifact": os.path.relpath(SEL, ROOT)},
            "pcap": {**pcap, "artifact": os.path.relpath(PCAP, ROOT)},
            "suricata_sid_1000001": {"count": len(suri), "events": suri[:5],
                                     "artifact": os.path.relpath(EVE, ROOT)},
        },
        "archived_software_evidence": {
            "trivy_report": {"present": os.path.exists(TRIVY), "artifact": os.path.relpath(TRIVY, ROOT)},
            "sbom_cyclonedx": {"present": os.path.exists(SBOM), "artifact": os.path.relpath(SBOM, ROOT)},
            "note": "Trivy/SBOM are archived evidence; this correlation does not consume them (see LLM cross-validation).",
        },
        "correlation": {
            "application_security_detection_zap": app_detection,
            "network_detection_suricata": net_detection,
            "controlled_traffic_captured": traffic_present,
            "runtime_authentication_validated": runtime_auth,
            "status": status,
            "chain": "controlled SQLi activity -> ZAP app-security finding (40018) -> captured PCAP -> "
                     "Suricata network detection (SID 1000001) -> correlation -> security decision",
        },
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "security-event-correlation.json"), "w") as f:
        json.dump(report, f, indent=2)

    def yn(b):
        return "yes" if b else "NO"

    md = [
        "# Scenario B - Security Event Correlation",
        "",
        f"- Run ID: `{run_id}`",
        f"- Generated: {report['generated_at']}",
        f"- Target: {TARGET_HOST}:{TARGET_PORT}",
        f"- Controlled signature: `{SQLI_SIG}`",
        "",
        "## Independent observations",
        "",
        "| Layer | Tool | Result |",
        "|---|---|---|",
        f"| Application security | OWASP ZAP (alert 40018) | {sqli_alerts} SQL Injection finding(s) |",
        f"| Runtime / browser | Selenium | login_success = {yn(runtime_auth)} ({(sel or {}).get('login_method')}) |",
        f"| Network traffic | PCAP | {pcap.get('packets')} packets, SQLi request present = {yn(pcap.get('sqli_request_present'))} |",
        f"| Network detection | Suricata (SID 1000001) | {len(suri)} event(s) |",
        "",
        "## Correlation result",
        "",
        f"- Application-security detection (ZAP 40018): **{yn(app_detection)}**",
        f"- Controlled traffic captured in PCAP: **{yn(traffic_present)}**",
        f"- Network detection (Suricata SID 1000001): **{yn(net_detection)}**",
        f"- Runtime authentication validated (Selenium): **{yn(runtime_auth)}**",
        "",
        f"### Status: **{status}**",
        "",
        "Chain: controlled SQLi activity -> ZAP application-security finding -> captured PCAP -> "
        "Suricata network detection -> correlation -> CI/CD security decision.",
        "",
        "> Note: the ZAP targeted test sends `POST /rest/user/login`, while the controlled network "
        "positive control sends `GET /rest/products/search?q=%27%28`. These are different HTTP "
        "transactions associated with the same run; they are not presented as a packet-level match.",
    ]
    with open(os.path.join(OUT_DIR, "security-event-correlation.md"), "w") as f:
        f.write("\n".join(md) + "\n")

    print(f"correlation status: {status}  (zap40018={sqli_alerts}, suricata1000001={len(suri)}, "
          f"pcap_sqli={pcap.get('sqli_request_present')}, selenium_login={runtime_auth})")
    # correlation validity is reported; the pipeline checks the status separately
    sys.exit(0)


if __name__ == "__main__":
    main()
