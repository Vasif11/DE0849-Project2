#!/bin/sh
# Runs INSIDE the UE container (telecom-lab-ueransim:3.3.0-p2). All requests go over the 5G user
# plane to the HTTPS gateway with genuine CA validation. Avoids host<->docker quoting problems.
#   usage: docker cp this file into the UE and run:  sh /tmp/ue_app_tests.sh
set -u
BASE="https://10.20.6.20"
CA="/etc/telecom-lab/ca.crt"
C="curl -s --cacert $CA --max-time 10"

csrf_from() {   # extract the hidden csrfmiddlewaretoken from a fetched page
  grep csrfmiddlewaretoken "$1" | sed -n 's/.*value="\([^"]*\)".*/\1/p' | head -n1
}

echo "## TLS versions (curl, CA-validated)"
$C --tlsv1.2 --tls-max 1.2 -o /dev/null -w 'TLS1.2 handshake HTTP %{http_code}\n' $BASE/health/
$C --tlsv1.3 --tls-max 1.3 -o /dev/null -w 'TLS1.3 handshake HTTP %{http_code}\n' $BASE/health/
printf 'TLS1.0 (must fail): '; $C --tlsv1.0 --tls-max 1.0 -o /dev/null -w 'HTTP %{http_code}\n' $BASE/health/ || echo "rejected (expected)"

echo
echo "## login flow"
rm -f /tmp/jar
$C -c /tmp/jar $BASE/accounts/login/ -o /tmp/login.html
LTOK=$(csrf_from /tmp/login.html)
$C -b /tmp/jar -c /tmp/jar -e $BASE/accounts/login/ \
   -d "username=securityadmin&password=SecureLab!2026&csrfmiddlewaretoken=$LTOK" \
   -o /dev/null -w 'login POST -> %{http_code} (redirect %{redirect_url})\n' $BASE/accounts/login/

echo
echo "## authenticated access"
$C -b /tmp/jar -o /dev/null -w 'auth GET /profile/ -> %{http_code}\n' $BASE/profile/
$C -b /tmp/jar $BASE/profile/ | grep -E 'Username|Authenticated' | sed 's/<[^>]*>//g;s/^ *//'
$C -b /tmp/jar -o /dev/null -w 'auth GET /feedback/ -> %{http_code}\n' $BASE/feedback/

echo
echo "## CSRF enforcement"
$C -b /tmp/jar -c /tmp/jar $BASE/feedback/ -o /tmp/fb.html
FTOK=$(csrf_from /tmp/fb.html)
echo "extracted feedback CSRF token length: $(printf %s "$FTOK" | wc -c)"
$C -b /tmp/jar -e $BASE/feedback/ -d "message=valid+csrf+test&csrfmiddlewaretoken=$FTOK" \
   -o /dev/null -w 'valid-CSRF   POST /feedback/ -> %{http_code} (expect 200)\n' $BASE/feedback/
$C -b /tmp/jar -e $BASE/feedback/ -d "message=missing+csrf" \
   -o /dev/null -w 'missing-CSRF POST /feedback/ -> %{http_code} (expect 403)\n' $BASE/feedback/

echo
echo "## security headers (HTTPS GET /)"
$C -D - -o /dev/null $BASE/ | grep -iE 'strict-transport-security|x-frame-options|x-content-type-options|referrer-policy'

echo
echo "## secure cookies (Set-Cookie on login)"
rm -f /tmp/j2
$C -c /tmp/j2 $BASE/accounts/login/ -o /tmp/l2.html
L2=$(csrf_from /tmp/l2.html)
$C -b /tmp/j2 -c /tmp/j2 -e $BASE/accounts/login/ -D - -o /dev/null \
   -d "username=securityadmin&password=SecureLab!2026&csrfmiddlewaretoken=$L2" $BASE/accounts/login/ \
   | grep -i 'set-cookie'
