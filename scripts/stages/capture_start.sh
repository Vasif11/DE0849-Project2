#!/usr/bin/env bash
# 2B-3 Start a fresh capture BEFORE the controlled SQLi activity. Runs a detached capture container
# in the Juice Shop network namespace so the window survives across Jenkins stages.
set -euo pipefail
WS="${WS:-$(cd "$(dirname "$0")/../.." && pwd)}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
OUT="$WS/security/traffic/scenario-b/ci"; mkdir -p "$OUT"; chmod 777 "$OUT"
rm -f "$OUT/juice-shop-ci-sqli.pcapng"
docker rm -f capture-"$RUN_ID" 2>/dev/null || true
# capture in Juice Shop's netns (observes all traffic to the controlled target)
docker run -d --name capture-"$RUN_ID" --network container:juice-shop -v "$OUT:/out" \
  jasonish/suricata:8.0 tcpdump -i eth0 -n -s 0 -w /out/juice-shop-ci-sqli.pcapng "tcp port 3000"
sleep 2
echo "capture started: capture-$RUN_ID"
