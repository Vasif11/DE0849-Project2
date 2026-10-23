#!/usr/bin/env bash
# Security Gate (modular stage). Reports tool result -> finding -> gate decision separately.
#   GATE_MODE=REPORT_ONLY (default) | ENFORCE
set -uo pipefail
WS="${WS:-$(cd "$(dirname "$0")/../.." && pwd)}"
GATE_MODE="${GATE_MODE:-REPORT_ONLY}"
S="$WS/security"
zap=$(jq '[.site[].alerts[]|select(.pluginid=="40018" or (.name|ascii_downcase|test("sql injection")))]|length' \
      "$S/reports/zap/scenario-b-ci-targeted/scenario-b-ci-targeted.json" 2>/dev/null || echo 0)
suri=$(grep -c '"signature_id":1000001' "$S/ids/scenario-b/ci/eve.json" 2>/dev/null || echo 0)
corr=$(jq -r '.correlation.status' "$S/correlation/scenario-b/security-event-correlation.json" 2>/dev/null || echo UNKNOWN)
high=$(jq '[.Results[]?.Vulnerabilities[]?|select(.Severity=="HIGH")]|length' "$S/scans/trivy-ci/juice-shop-v20.2.0.json" 2>/dev/null || echo 0)
crit=$(jq '[.Results[]?.Vulnerabilities[]?|select(.Severity=="CRITICAL")]|length' "$S/scans/trivy-ci/juice-shop-v20.2.0.json" 2>/dev/null || echo 0)

echo "TOOL RESULTS:  ZAP_40018=$zap  Suricata_1000001=$suri  Correlation=$corr  Trivy_HIGH=$high  Trivy_CRITICAL=$crit"
gate=PASS; reasons=""
[ "$zap"  -ge 1 ]        || { gate=FAIL; reasons="$reasons zap40018-missing;"; }
[ "$suri" -ge 1 ]        || { gate=FAIL; reasons="$reasons suricata1000001-missing;"; }
[ "$corr" = CORRELATED ] || { gate=FAIL; reasons="$reasons correlation;"; }
if [ "$GATE_MODE" = ENFORCE ] && [ $((high + crit)) -gt 0 ]; then
  gate=FAIL; reasons="$reasons trivy-high/critical(ENFORCE);"
  echo "FINDING: Trivy HIGH/CRITICAL=$((high+crit)) -> ENFORCE threshold violated (blocking)"
else
  echo "FINDING: Trivy HIGH/CRITICAL=$((high+crit)) -> informational under $GATE_MODE"
fi
echo "GATE_DECISION ($GATE_MODE): $gate${reasons:+  reasons:$reasons}"
[ "$gate" = PASS ] && exit 0 || exit 1
