#!/usr/bin/env bash
# Shared configuration/helpers for Project 2 scripts.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$REPO_DIR/deploy"
RESULTS="$REPO_DIR/results"
SECURITY="$REPO_DIR/security"
PY=${PY:-/opt/p1venv/bin/python}

DC_5G="docker compose -f $DEPLOY/docker-compose.5g.yml"
DC_APP="docker compose -f $DEPLOY/docker-compose.app.yml"

# Scenario A endpoints
NGINX_IP=10.20.6.20
DJANGO_IP=10.20.8.20
C_UE=scenario-b-ue
C_NGINX=scenario-b-nginx
C_DJANGO=scenario-b-django
UE_TUN=uesimtun0
CA_CRT=/etc/telecom-lab/ca.crt

require_root() { if [[ $EUID -ne 0 ]]; then echo "run as root (sudo)"; exit 1; fi; }
log() { printf '\n\033[1;34m[%s] %s\033[0m\n' "$(date +%T)" "$*"; }

cpid() { docker inspect -f '{{.State.Pid}}' "$1"; }
cns()  { local c=$1; shift; nsenter -t "$(cpid "$c")" -n "$@"; }   # run host binary in a container netns
ue()   { cns "$C_UE" "$@"; }
ue_ip() { ue ip -o -4 addr show dev "$UE_TUN" 2>/dev/null | awk '{split($4,a,"/"); print a[1]}'; }

wait_pdu() {
  local t=${1:-120}
  for _ in $(seq 1 "$t"); do [[ -n "$(ue_ip 2>/dev/null)" ]] && return 0; sleep 1; done
  echo "no PDU session after ${t}s" >&2; return 1
}

# run_logged <file> <cmd...> : print the command + output and append to an evidence file
run_logged() { local out=$1; shift; { echo "\$ $*"; "$@" 2>&1 || true; echo; } | tee -a "$out"; }

# a UE-side curl against the HTTPS gateway, trusting the lab CA (uses a disposable curl container
# on the UE network namespace is not possible; instead we use the UE container's own curl)
ue_curl() { docker exec "$C_UE" curl "$@"; }
