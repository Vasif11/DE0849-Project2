#!/usr/bin/env bash
# Local laboratory PKI for the Scenario A application gateway.
#
#   Telecom Lab Root CA  ->  server certificate (Nginx, 10.20.6.20)
#
# Outputs:
#   pki/ca.crt                 CA certificate       (public; committed, mounted read-only into the UE)
#   pki/ca.key                 CA private key       (SECRET; stays on the host, never committed/mounted)
#   secrets/tls/server.crt     server certificate   (mounted read-only into Nginx)
#   secrets/tls/server.key     server private key   (SECRET; mounted read-only into Nginx, not committed)
#
# The server certificate SAN contains IP:10.20.6.20, DNS:telecom-lab.local, DNS:localhost.
set -euo pipefail
cd "$(dirname "$0")/.."
PKI=pki
TLS=secrets/tls
mkdir -p "$PKI" "$TLS"

DAYS_CA=3650
DAYS_SRV=825
SERVER_IP=10.20.6.20

if [[ -f "$PKI/ca.crt" && -f "$PKI/ca.key" ]]; then
  echo "CA already exists ($PKI/ca.crt), reusing it."
else
  echo "Creating Telecom Lab Root CA..."
  openssl genrsa -out "$PKI/ca.key" 4096
  openssl req -x509 -new -nodes -key "$PKI/ca.key" -sha256 -days "$DAYS_CA" \
    -subj "/C=LV/O=Telecom Lab/OU=DE0849 Project 2/CN=Telecom Lab Root CA" \
    -out "$PKI/ca.crt"
fi

echo "Creating server key and CSR for $SERVER_IP..."
openssl genrsa -out "$TLS/server.key" 2048
openssl req -new -key "$TLS/server.key" \
  -subj "/C=LV/O=Telecom Lab/OU=DE0849 Project 2/CN=telecom-lab.local" \
  -out "$TLS/server.csr"

cat > "$TLS/server-ext.cnf" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names
[alt_names]
IP.1=$SERVER_IP
DNS.1=telecom-lab.local
DNS.2=localhost
EOF

echo "Signing server certificate with the lab CA..."
openssl x509 -req -in "$TLS/server.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
  -CAcreateserial -sha256 -days "$DAYS_SRV" -extfile "$TLS/server-ext.cnf" \
  -out "$TLS/server.crt"

rm -f "$TLS/server.csr" "$TLS/server-ext.cnf"
chmod 600 "$PKI/ca.key" "$TLS/server.key"

echo "--- CA certificate:"
openssl x509 -in "$PKI/ca.crt" -noout -subject -issuer -dates
echo "--- server certificate:"
openssl x509 -in "$TLS/server.crt" -noout -subject -issuer -dates -ext subjectAltName
echo "PKI ready."
