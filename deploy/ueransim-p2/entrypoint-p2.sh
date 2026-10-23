#!/bin/bash
# Start the UERANSIM UE and maintain the persistent application route to the N6 subnet.
#
#   10.20.6.0/24 dev uesimtun0
#
# uesimtun0 is created only after the PDU session is established, and it is re-created whenever the
# session re-establishes, so the route is (re)applied by a small background loop rather than once.
set -e

APP_SUBNET="${APP_SUBNET:-10.20.6.0/24}"
UE_TUN="${UE_TUN:-uesimtun0}"

route_keeper() {
  while true; do
    if ip link show "$UE_TUN" >/dev/null 2>&1; then
      # add the route only if it is missing (replace is idempotent and cheap)
      ip route replace "$APP_SUBNET" dev "$UE_TUN" 2>/dev/null || true
    fi
    sleep 5
  done
}

route_keeper &
# hand control to the normal UERANSIM UE process (uses the image's own nr-ue invocation)
exec nr-ue -c /config/ue.yaml
