#!/usr/bin/env bash
# Scenario A acceptance test (Phases 1A-1E). Every application request is made FROM the UE
# container over the real 5G user plane (UE 10.45.0.x -> uesimtun0 -> UPF -> N6 -> Nginx HTTPS),
# with genuine CA validation (curl --cacert), never -k. Evidence is saved under results/scenario-a/.
source "$(dirname "$0")/lib.sh"
require_root

OUT="$RESULTS/scenario-a"
mkdir -p "$OUT"; rm -f "$OUT"/*.txt
BASE="https://$NGINX_IP"
# curl inside the UE container, trusting the lab CA and sending the HTTPS Referer Django expects
UC="docker exec scenario-b-ue curl -s --cacert $CA_CRT --max-time 10"

log "1A - 5G path and persistent route"
E="$OUT/1A_path.txt"
run_logged "$E" bash -c "echo 'UE PDU address:'; nsenter -t $(cpid $C_UE) -n ip -br addr show $UE_TUN"
run_logged "$E" docker exec $C_UE ip route get $NGINX_IP
run_logged "$E" docker exec $C_UE ping -c 3 -W 2 $NGINX_IP

log "1B - Django application (internal)"
E="$OUT/1B_django.txt"
run_logged "$E" docker inspect -f '{{.Name}} health={{.State.Health.Status}} image={{.Config.Image}}' $C_DJANGO
run_logged "$E" docker exec $C_NGINX curl -s http://$DJANGO_IP:8000/health/
run_logged "$E" docker exec $C_DJANGO sh -c 'ls -la /app/data/db.sqlite3'
run_logged "$E" docker network inspect scenario-b-app --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}'

log "1C - TLS gateway: certificate (from the host-side PKI) and HTTP->HTTPS redirect"
E="$OUT/1C_tls.txt"
# certificate details come from the generated server cert (UE image has no openssl; TLS version
# handshakes are verified from the UE with curl in ue_app_tests.sh below)
run_logged "$E" openssl x509 -in "$REPO_DIR/secrets/tls/server.crt" -noout -subject -issuer -dates -ext subjectAltName
run_logged "$E" bash -c "$UC -o /dev/null -D - http://$NGINX_IP/ | grep -iE 'HTTP/|location'"
run_logged "$E" bash -c "$UC -o /dev/null -w 'HTTPS GET / -> %{http_code}\n' $BASE/"

log "1C/1D - public endpoints (GET) over the 5G path"
E="$OUT/1D_public_endpoints.txt"
for p in / /health/ /api/status/ "/search/?q=security"; do
  run_logged "$E" bash -c "$UC -o /dev/null -w 'GET $p -> %{http_code}\n' '$BASE$p'"
done
run_logged "$E" bash -c "$UC $BASE/health/"
run_logged "$E" bash -c "$UC $BASE/api/status/"

log "1D - unauthenticated protected resources (expect 302 to login)"
E="$OUT/1D_authz.txt"
for p in /profile/ /feedback/; do
  run_logged "$E" bash -c "$UC -o /dev/null -w 'unauth GET $p -> %{http_code} (redirect: %{redirect_url})\n' '$BASE$p'"
done

log "1C/1D/1E - TLS versions, login, authz, CSRF, headers, cookies (run inside the UE container)"
E="$OUT/1E_app_security_from_ue.txt"
sed -i 's/\r$//' "$REPO_DIR/scripts/ue_app_tests.sh"
docker cp "$REPO_DIR/scripts/ue_app_tests.sh" $C_UE:/tmp/ue_app_tests.sh
docker exec $C_UE sh /tmp/ue_app_tests.sh | tee "$E"

echo "Evidence saved to $OUT"
