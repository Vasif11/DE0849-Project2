# Scenario A secure application gateway (telecom-lab-nginx:p2)
#   nginx:latest + iproute2 (persistent route to the UE PDU pool) + TLS config
FROM nginx:latest

RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 \
 && rm -rf /var/lib/apt/lists/*

COPY default.conf /etc/nginx/conf.d/default.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443
ENTRYPOINT ["/entrypoint.sh"]
