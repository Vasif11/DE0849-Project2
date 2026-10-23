#!/usr/bin/env bash
# 2C Stop the capture and validate that a fresh, non-empty PCAP with the controlled SQLi traffic exists.
set -euo pipefail
WS="${WS:-$(cd "$(dirname "$0")/../.." && pwd)}"
RUN_ID="${RUN_ID:-}"
PCAP="$WS/security/traffic/scenario-b/ci/juice-shop-ci-sqli.pcapng"
sleep 1
docker stop capture-"$RUN_ID" >/dev/null 2>&1 || true
docker rm   capture-"$RUN_ID" >/dev/null 2>&1 || true
[ -s "$PCAP" ] || { echo "PCAP empty/missing"; exit 1; }
pkts=$(tshark -r "$PCAP" 2>/dev/null | wc -l)
sqli=$(tshark -r "$PCAP" -Y http.request -T fields -e http.request.uri 2>/dev/null | grep -c '%27%28' || true)
echo "PCAP packets=$pkts sqli_requests=$sqli"
[ "$sqli" -ge 1 ] || { echo "controlled SQLi request not present in PCAP"; exit 1; }
