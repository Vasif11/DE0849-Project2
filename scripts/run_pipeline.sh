#!/usr/bin/env bash
# Scenario B Security CI/CD pipeline (orchestrator).
#
# Executes the guidebook's mandatory stage order (2A Preflight -> 2B -> 2C -> 2C-Adv -> 2D -> 2E ->
# Archive -> Security Gate). This is the reproducible, Jenkins-equivalent runner: every stage uses
# the same tool containers and evidence paths as the Jenkinsfile. On the 4 GB lab host it is the
# primary execution path; the Jenkinsfile (jenkins/Jenkinsfile) defines the identical stages for a
# larger host. Each stage prints TOOL RESULT / FINDING / GATE separately.
#
#   GATE_MODE=REPORT_ONLY|ENFORCE   (default REPORT_ONLY)
source "$(dirname "$0")/lib.sh"
require_root
# lib.sh enables `set -e`; the pipeline intentionally has non-zero stage exits (ZAP warnings=2,
# Trivy threshold, etc.) that are captured per stage, so disable errexit here.
set +e
set -u

GATE_MODE="${GATE_MODE:-REPORT_ONLY}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"; export RUN_ID
JUICE=10.20.10.20; JUICE_PORT=3000; JUICE_URL="http://$JUICE:$JUICE_PORT"
GRID_URL="http://10.20.10.30:4444"
NET=scenario-b-security
SEC="$SECURITY"
PY=/opt/p1venv/bin/python

ZAP_IMG=ghcr.io/zaproxy/zaproxy:stable
SURI_IMG=jasonish/suricata:8.0
TRIVY_IMG=aquasec/trivy:0.75.0
SYFT_IMG=anchore/syft:v1.52.0
JUICE_IMG=bkimminich/juice-shop:v20.2.0

# evidence directories
ZAP_BASE="$SEC/reports/zap/scenario-b-ci"
ZAP_TGT="$SEC/reports/zap/scenario-b-ci-targeted"
SEL_EV="$SEC/selenium/evidence"
CAP_DIR="$SEC/traffic/scenario-b/ci"
IDS_DIR="$SEC/ids/scenario-b/ci"
TRIVY_DIR="$SEC/scans/trivy-ci"
SBOM_DIR="$SEC/sbom-ci"
CORR_DIR="$SEC/correlation/scenario-b"
PCAP="$CAP_DIR/juice-shop-ci-sqli.pcapng"
ARCHIVE="$REPO_DIR/ci-artifacts/$RUN_ID"
mkdir -p "$ZAP_BASE" "$ZAP_TGT" "$SEL_EV" "$CAP_DIR" "$IDS_DIR" "$TRIVY_DIR" "$SBOM_DIR" "$CORR_DIR" "$ARCHIVE"
chmod -R 777 "$ZAP_BASE" "$ZAP_TGT" "$CAP_DIR" "$IDS_DIR" "$TRIVY_DIR" "$SBOM_DIR" 2>/dev/null || true

STATUS_FILE="$ARCHIVE/pipeline-status.txt"
: > "$STATUS_FILE"
record() { echo "$1" | tee -a "$STATUS_FILE"; }
stage()  { log "STAGE $*"; }

# ============================================================ 1. Scenario A 1E acceptance
stage "Scenario A Step 1E acceptance (reference baseline)"
# The secure app path was verified in results/scenario-a/. Here we only confirm the evidence exists.
if [ -f "$RESULTS/scenario-a/1E_app_security_from_ue.txt" ]; then
  record "1E_ACCEPTANCE=PRESENT"
else
  record "1E_ACCEPTANCE=MISSING"
fi

# ============================================================ 2A Preflight
stage "2A Preflight - environment acceptance"
PRE="$ARCHIVE/preflight.json"; PF_OK=1
jq_ok=$(command -v jq >/dev/null && echo yes || echo no)
tshark_ok=$(command -v tshark >/dev/null && echo yes || echo no)
juice_http=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$JUICE_URL/rest/admin/application-version" || echo 000)
grid_ready=$(curl -s --max-time 10 "$GRID_URL/status" | jq -r '.value.ready' 2>/dev/null || echo false)
img_present() { docker image inspect "$1" >/dev/null 2>&1 && echo yes || echo no; }
net_present=$(docker network inspect "$NET" >/dev/null 2>&1 && echo yes || echo no)
sid_loaded=$(grep -q 'sid:1000001' "$SEC/ids/rules/scenario-b-local.rules" && echo yes || echo no)
plan_present=$([ -f "$SEC/zap/plan.yaml" ] && echo yes || echo no)
[ "$juice_http" = "200" ] || PF_OK=0
[ "$grid_ready" = "true" ] || PF_OK=0
[ "$net_present" = "yes" ] || PF_OK=0
[ "$sid_loaded" = "yes" ] || PF_OK=0
cat > "$PRE" <<EOF
{
  "run_id": "$RUN_ID", "generated_at": "$(date -Is)",
  "jenkins_equivalent_runner": true,
  "checks": {
    "jq": "$jq_ok", "tshark": "$tshark_ok",
    "juice_shop_http": "$juice_http", "juice_shop_target": "$JUICE_URL",
    "selenium_grid_ready": "$grid_ready",
    "security_net_present": "$net_present",
    "zap_image": "$(img_present $ZAP_IMG)", "suricata_image": "$(img_present $SURI_IMG)",
    "trivy_image": "$(img_present $TRIVY_IMG)", "syft_image": "$(img_present $SYFT_IMG)",
    "suricata_sid_1000001_loaded": "$sid_loaded", "zap_plan_present": "$plan_present"
  },
  "decision": "$([ $PF_OK -eq 1 ] && echo PASS || echo FAIL)"
}
EOF
cat "$PRE"
if [ $PF_OK -ne 1 ]; then record "PREFLIGHT=FAIL"; log "Preflight FAILED - aborting"; exit 1; fi
record "PREFLIGHT=PASS"

# ============================================================ 2B-1 ZAP Baseline
stage "2B-1 ZAP Baseline scan"
docker run --rm --network "$NET" -v "$ZAP_BASE:/zap/wrk:rw" "$ZAP_IMG" \
  zap-baseline.py -t "$JUICE_URL" -m 2 -J scenario-b-ci.json -w scenario-b-ci.md -r scenario-b-ci.html \
  > "$ZAP_BASE/zap-baseline-console.txt" 2>&1
ZAP_BASE_EXIT=$?
record "ZAP_BASELINE_EXIT=$ZAP_BASE_EXIT"   # 2 = warnings found (not a build failure by itself)
baseline_alerts=$(jq '[.site[].alerts[]] | length' "$ZAP_BASE/scenario-b-ci.json" 2>/dev/null || echo 0)
record "ZAP_BASELINE_ALERTS=$baseline_alerts"

# ============================================================ 2B-2 Selenium runtime/auth
stage "2B-2 Selenium runtime and authentication validation"
RUN_ID="$RUN_ID" SELENIUM_URL="$GRID_URL" JUICE_URL="$JUICE_URL" \
  "$PY" "$SEC/selenium/login_storage_test.py" > "$SEL_EV/selenium-console.txt" 2>&1
SEL_EXIT=$?
sel_login=$(jq -r '.login_success' "$SEL_EV/juice-shop-auth-storage.json" 2>/dev/null || echo false)
record "SELENIUM_EXIT=$SEL_EXIT SELENIUM_LOGIN=$sel_login"

# ============================================================ 2B-3 Start fresh capture
stage "2B-3 Start fresh packet capture (BEFORE generating SQLi traffic)"
# capture to a local ext4 path first; writing pcaps straight to the Windows (9p) mount loses packets
TMP_PCAP="/tmp/juice-shop-ci-sqli-$RUN_ID.pcapng"
rm -f "$PCAP" "$TMP_PCAP"
CAP_START=$(date -Is)
tcpdump -i br-sec -n -s 0 -B 16384 -w "$TMP_PCAP" "tcp port $JUICE_PORT and host $JUICE" >/dev/null 2>&1 &
CAP_PID=$!
sleep 2
record "CAPTURE_PID=$CAP_PID CAPTURE_START=$CAP_START"

# ============================================================ 2B-4 Controlled SQLi positive control
stage "2B-4 Generate controlled SQLi network positive control"
# deterministic request matched by Suricata SID 1000001
SQLI_REQ="$JUICE_URL/rest/products/search?q=%27%28"
curl -s -o "$ARCHIVE/controlled-sqli-response.json" -w 'controlled SQLi GET -> HTTP %{http_code}\n' "$SQLI_REQ" | tee -a "$STATUS_FILE"
# a couple of benign requests so the traffic-intelligence baseline has normal traffic too
for p in "/rest/products/search?q=apple" "/rest/products/search?q=juice" "/" "/rest/admin/application-version"; do
  curl -s -o /dev/null "$JUICE_URL$p"
done
sleep 2

# ============================================================ 2B-5 Targeted ZAP SQLi test
stage "2B-5 Targeted ZAP SQL Injection test (alert 40018)"
cp "$SEC/zap/plan.yaml" "$ZAP_TGT/plan.yaml"           # persistent plan
cp "$SEC/zap/plan.yaml" "$ARCHIVE/plan-$RUN_ID.yaml"   # executed plan tied to RUN_ID
docker run --rm --network "$NET" -v "$ZAP_TGT:/zap/wrk:rw" "$ZAP_IMG" \
  zap.sh -cmd -autorun /zap/wrk/plan.yaml > "$ZAP_TGT/zap-targeted-console.txt" 2>&1
ZAP_TGT_EXIT=$?
# move reports written under /zap/wrk/reports to the expected path
[ -f "$ZAP_TGT/reports/scenario-b-ci-targeted.json" ] && cp "$ZAP_TGT/reports/scenario-b-ci-targeted.json" "$ZAP_TGT/scenario-b-ci-targeted.json"
[ -f "$ZAP_TGT/reports/scenario-b-ci-targeted.md" ] && cp "$ZAP_TGT/reports/scenario-b-ci-targeted.md" "$ZAP_TGT/scenario-b-ci-targeted.md"
zap_sqli=$(jq '[.site[].alerts[] | select((.pluginid=="40018") or (.name|ascii_downcase|test("sql injection")))] | length' "$ZAP_TGT/scenario-b-ci-targeted.json" 2>/dev/null || echo 0)
record "ZAP_TARGETED_EXIT=$ZAP_TGT_EXIT ZAP_SQLI_40018=$zap_sqli"

# ============================================================ 2C Stop capture + validate PCAP
stage "2C Stop capture and validate fresh PCAP"
kill -INT "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null
cp "$TMP_PCAP" "$PCAP" 2>/dev/null || true
CAP_END=$(date -Is)
pcap_size=$(stat -c%s "$PCAP" 2>/dev/null || echo 0)
pcap_pkts=$(tshark -r "$PCAP" 2>/dev/null | wc -l)
pcap_has_sqli=$(tshark -r "$PCAP" -Y 'http.request' -T fields -e http.request.uri 2>/dev/null | grep -c '%27%28' || true)
record "PCAP_SIZE=$pcap_size PCAP_PACKETS=$pcap_pkts PCAP_SQLI_REQUESTS=$pcap_has_sqli CAPTURE_END=$CAP_END"
[ "$pcap_size" -gt 0 ] || { record "PCAP=EMPTY"; log "PCAP empty - aborting"; exit 1; }

# ============================================================ 2C Suricata offline analysis
stage "2C Suricata offline PCAP analysis (SID 1000001)"
rm -f "$IDS_DIR"/eve.json "$IDS_DIR"/fast.log "$IDS_DIR"/stats.log "$IDS_DIR"/suricata.log
# Use the image's full default suricata.yaml (correct HTTP app-layer parsing) and load ONLY the
# Scenario B local rule via -S; -k none skips offloaded/incorrect pcap checksums.
docker run --rm \
  -v "$PCAP:/pcap/juice-shop-ci-sqli.pcapng:ro" \
  -v "$SEC/ids/rules:/rules:ro" \
  -v "$IDS_DIR:/output:rw" \
  "$SURI_IMG" suricata -S /rules/scenario-b-local.rules -k none \
  -r /pcap/juice-shop-ci-sqli.pcapng -l /output \
  > "$IDS_DIR/suricata-console.txt" 2>&1
suri_sid=$(grep -c '"signature_id":1000001' "$IDS_DIR/eve.json" 2>/dev/null || echo 0)
record "SURICATA_SID_1000001=$suri_sid"

# ============================================================ 2C-Advanced Traffic intelligence
stage "2C-Advanced Traffic intelligence / analytics"
RUN_ID="$RUN_ID" PCAP="$PCAP" "$PY" "$SEC/traffic-intelligence/extract_features.py" 2>&1 | tee -a "$STATUS_FILE" || true

# ============================================================ 2D Trivy scan
stage "2D Trivy image vulnerability scan"
docker run --rm -v "$TRIVY_DIR:/out:rw" -v trivy-cache:/root/.cache/ "$TRIVY_IMG" \
  image --scanners vuln --format json -o /out/juice-shop-v20.2.0.json "$JUICE_IMG" \
  > "$TRIVY_DIR/trivy-console.txt" 2>&1
TRIVY_EXIT=$?
trivy_high=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$TRIVY_DIR/juice-shop-v20.2.0.json" 2>/dev/null || echo 0)
trivy_crit=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$TRIVY_DIR/juice-shop-v20.2.0.json" 2>/dev/null || echo 0)
record "TRIVY_EXIT=$TRIVY_EXIT TRIVY_HIGH=$trivy_high TRIVY_CRITICAL=$trivy_crit"

# ============================================================ 2D Syft SBOM
stage "2D Syft CycloneDX SBOM generation"
docker run --rm "$SYFT_IMG" "$JUICE_IMG" -o cyclonedx-json > "$SBOM_DIR/juice-shop-v20.2.0.cdx.json" 2>"$SBOM_DIR/syft-console.txt"
sbom_components=$(jq '.components | length' "$SBOM_DIR/juice-shop-v20.2.0.cdx.json" 2>/dev/null || echo 0)
record "SBOM_COMPONENTS=$sbom_components"

# ============================================================ 2E Correlation
stage "2E Security event correlation"
RUN_ID="$RUN_ID" "$PY" "$SEC/correlation/scenario-b/correlate_scenario_b.py" 2>&1 | tee -a "$STATUS_FILE"
corr_status=$(jq -r '.correlation.status' "$CORR_DIR/security-event-correlation.json" 2>/dev/null || echo UNKNOWN)
record "CORRELATION=$corr_status"

# ============================================================ Archive
stage "Evidence archive"
cp -r "$ZAP_BASE" "$ZAP_TGT" "$SEL_EV" "$CAP_DIR" "$IDS_DIR" "$TRIVY_DIR" "$SBOM_DIR" "$CORR_DIR" \
      "$SEC/traffic-intelligence" "$ARCHIVE/" 2>/dev/null || true
record "ARCHIVE=$ARCHIVE"

# ============================================================ Security Gate
stage "Security Gate ($GATE_MODE)"
# positive controls (their own expected results)
PC_ZAP=$([ "$zap_sqli" -ge 1 ] && echo PASS || echo FAIL)
PC_SURI=$([ "$suri_sid" -ge 1 ] && echo PASS || echo FAIL)
record "POSITIVE_CONTROL_ZAP_40018=$PC_ZAP"
record "POSITIVE_CONTROL_SURICATA_1000001=$PC_SURI"
record "CORRELATION_STATUS=$corr_status"
# Trivy HIGH/CRITICAL policy: informational in REPORT_ONLY, blocking in ENFORCE
TRIVY_BLOCK=$(( trivy_high + trivy_crit ))
GATE=PASS; REASON=""
[ "$PC_ZAP" = PASS ]  || { GATE=FAIL; REASON="$REASON zap40018-missing;"; }
[ "$PC_SURI" = PASS ] || { GATE=FAIL; REASON="$REASON suricata1000001-missing;"; }
[ "$corr_status" = CORRELATED ] || { GATE=FAIL; REASON="$REASON correlation-not-correlated;"; }
if [ "$GATE_MODE" = ENFORCE ] && [ "$TRIVY_BLOCK" -gt 0 ]; then
  GATE=FAIL; REASON="$REASON trivy-high/critical=$TRIVY_BLOCK(ENFORCE);"
fi
echo
record "========== SECURITY GATE =========="
record "GATE_MODE=$GATE_MODE"
record "TRIVY HIGH=$trivy_high CRITICAL=$trivy_crit -> $([ "$GATE_MODE" = ENFORCE ] && echo 'blocking threshold applied' || echo 'informational (REPORT_ONLY)')"
record "GATE_DECISION=$GATE${REASON:+  (reasons:$REASON)}"
cp "$STATUS_FILE" "$REPO_DIR/results/scenario-b-pipeline-status.txt" 2>/dev/null || true
log "Pipeline finished: RUN_ID=$RUN_ID GATE=$GATE ($GATE_MODE)"
[ "$GATE" = PASS ] && exit 0 || exit 1
