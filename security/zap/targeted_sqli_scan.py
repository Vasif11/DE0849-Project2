#!/usr/bin/env python3
"""Targeted ZAP SQL-Injection active scan via the ZAP API (deterministic positive control).

Juice Shop is an Angular SPA, so the traditional spider does not map its REST endpoints. This script
drives a ZAP daemon through its API: it seeds the known SQLi-vulnerable endpoint
(/rest/products/search?q=) and the login, runs an active scan limited to the SQL Injection scanner
(plugin 40018) at HIGH strength / LOW threshold, waits for completion, and writes a traditional-json
report. Expected positive-control result: at least one alert 40018.

Env: ZAP_BASE (default http://127.0.0.1:8090), TARGET (default http://10.20.10.20:3000),
     OUT_JSON (report path).
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request

ZAP = os.environ.get("ZAP_BASE", "http://127.0.0.1:8090")
TARGET = os.environ.get("TARGET", "http://10.20.10.20:3000")
OUT_JSON = os.environ.get("OUT_JSON", "scenario-b-ci-targeted.json")
SQLI_PLUGIN = "40018"
SEED_URLS = [f"{TARGET}/rest/products/search?q=test", f"{TARGET}/rest/products/search?q=apple"]


def api(path, **params):
    url = f"{ZAP}/JSON/{path}/?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=120) as r:
        return json.load(r)


def api_other(path, **params):
    url = f"{ZAP}/OTHER/{path}/?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def wait_ready(timeout=60):
    for _ in range(timeout):
        try:
            api("core/view/version")
            return True
        except Exception:
            time.sleep(1)
    return False


def main():
    if not wait_ready():
        print("ZAP API not reachable", file=sys.stderr)
        sys.exit(2)
    print("ZAP version:", api("core/view/version").get("version"))

    # seed the injectable endpoints through ZAP so they enter the sites tree with their parameters
    for u in SEED_URLS:
        try:
            api("core/action/accessUrl", url=u, followRedirects="true")
        except Exception as e:
            print("accessUrl warn:", e)
    # seed the login POST body too
    try:
        api("core/action/sendRequest",
            request=f"POST /rest/user/login HTTP/1.1\r\nHost: 10.20.10.20:3000\r\n"
                    f"Content-Type: application/json\r\nContent-Length: 44\r\n\r\n"
                    f'{{"email":"test@test.local","password":"x"}}')
    except Exception as e:
        print("sendRequest warn:", e)
    time.sleep(2)

    # enable ONLY the SQL Injection scanner (40018) at HIGH strength / LOW threshold
    api("ascan/action/disableAllScanners")
    api("ascan/action/enableScanners", ids=SQLI_PLUGIN)
    api("ascan/action/setScannerAttackStrength", id=SQLI_PLUGIN, attackStrength="HIGH")
    api("ascan/action/setScannerAlertThreshold", id=SQLI_PLUGIN, alertThreshold="LOW")

    scan_id = api("ascan/action/scan", url=SEED_URLS[0], recurse="true",
                  inScopeOnly="false", scanPolicyName="")["scan"]
    print("active scan id:", scan_id)
    for _ in range(300):
        st = api("ascan/view/status", scanId=scan_id).get("status")
        if st == "100":
            break
        time.sleep(1)
    print("active scan status:", api("ascan/view/status", scanId=scan_id).get("status"))

    # also scan the login endpoint
    try:
        sid2 = api("ascan/action/scan", url=f"{TARGET}/rest/user/login", recurse="false",
                   inScopeOnly="false")["scan"]
        for _ in range(120):
            if api("ascan/view/status", scanId=sid2).get("status") == "100":
                break
            time.sleep(1)
    except Exception as e:
        print("login scan warn:", e)

    alerts = api("alert/view/alerts", baseurl=TARGET, start="0", count="9999").get("alerts", [])
    sqli = [a for a in alerts if str(a.get("pluginId")) == SQLI_PLUGIN
            or "sql injection" in a.get("alert", "").lower()]
    print(f"total alerts: {len(alerts)}, SQL Injection (40018): {len(sqli)}")

    # build a traditional-json-style report (site[].alerts[]) from the alerts API, grouping by plugin
    grouped = {}
    for a in alerts:
        pid = str(a.get("pluginId"))
        g = grouped.setdefault(pid, {"pluginid": pid, "name": a.get("alert"), "riskcode": a.get("riskcode"),
                                     "riskdesc": a.get("risk"), "count": 0, "instances": []})
        g["count"] += 1
        g["instances"].append({"uri": a.get("url"), "param": a.get("param"), "attack": a.get("attack"),
                               "evidence": a.get("evidence")})
    report = {"@programName": "ZAP", "@version": api("core/view/version").get("version"),
              "site": [{"@name": TARGET, "@host": "10.20.10.20", "@port": "3000",
                        "alerts": list(grouped.values())}]}
    os.makedirs(os.path.dirname(os.path.abspath(OUT_JSON)), exist_ok=True)
    with open(OUT_JSON, "w") as f:
        json.dump(report, f, indent=2)
    # also a compact summary
    with open(os.path.splitext(OUT_JSON)[0] + "-sqli-summary.json", "w") as f:
        json.dump({"target": TARGET, "sql_injection_40018_count": len(sqli),
                   "evidence": [{"url": a.get("url"), "param": a.get("param"),
                                 "attack": a.get("attack"), "risk": a.get("risk")} for a in sqli[:10]]},
                  f, indent=2)
    print("40018 findings:", len(sqli))
    sys.exit(0 if len(sqli) >= 1 else 1)


if __name__ == "__main__":
    main()
