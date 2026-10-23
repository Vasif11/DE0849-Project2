#!/usr/bin/env bash
# 2A Preflight (modular stage used by the Jenkinsfile). Fails fast if the environment is not ready.
set -uo pipefail
WS="${WS:-$(cd "$(dirname "$0")/../.." && pwd)}"
JUICE_URL="${JUICE_URL:-http://10.20.10.20:3000}"
GRID_URL="${GRID_URL:-http://10.20.10.30:4444}"
NET="${NET:-scenario-b-security}"
ok=1
command -v jq >/dev/null     || { echo "jq missing"; ok=0; }
command -v tshark >/dev/null || { echo "tshark missing"; ok=0; }
[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$JUICE_URL/rest/admin/application-version")" = 200 ] || { echo "Juice Shop not reachable"; ok=0; }
[ "$(curl -s --max-time 10 "$GRID_URL/status" | jq -r '.value.ready' 2>/dev/null)" = true ] || { echo "Selenium Grid not ready"; ok=0; }
docker network inspect "$NET" >/dev/null 2>&1 || { echo "security network missing"; ok=0; }
grep -q 'sid:1000001' "$WS/security/ids/rules/scenario-b-local.rules" || { echo "SID 1000001 not loaded"; ok=0; }
[ -f "$WS/security/zap/plan.yaml" ] || { echo "ZAP plan.yaml missing"; ok=0; }
[ $ok -eq 1 ] && { echo "Preflight PASS"; exit 0; } || { echo "Preflight FAIL"; exit 1; }
