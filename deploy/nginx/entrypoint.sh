#!/bin/bash
# Add the return route to the UE PDU pool, then start Nginx.
#
# Nginx terminates on the N6 data network (dn-net, 10.20.6.20). Replies to the UE (10.45.0.x)
# must be sent to the UPF (10.20.6.14), not the Docker bridge gateway, so the response re-enters
# the 5G user plane. Requires NET_ADMIN and iproute2.
set -e

UE_POOL="${UE_POOL:-10.45.0.0/16}"
UPF_N6="${UPF_N6:-10.20.6.14}"

ip route replace "$UE_POOL" via "$UPF_N6" 2>/dev/null \
  && echo "[nginx] route to UE pool $UE_POOL via UPF $UPF_N6 installed" \
  || echo "[nginx] WARNING: could not install route to $UE_POOL (is the UPF up and NET_ADMIN granted?)"

exec nginx -g 'daemon off;'
