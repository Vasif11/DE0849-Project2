# Project 2 custom UE image (telecom-lab-ueransim:3.3.0-p2)
# Extends the Project 1 UERANSIM UE with a startup mechanism that keeps the application route
#   10.20.6.0/24 -> uesimtun0
# so the N6/data-network subnet is reached through the 5G PDU tunnel after any UE recreation.
FROM gradiant/ueransim:3.3.0

COPY entrypoint-p2.sh /entrypoint-p2.sh
# the base image is built on Ubuntu; make sure the wrapper is executable
USER root
RUN chmod +x /entrypoint-p2.sh

ENTRYPOINT ["/entrypoint-p2.sh"]
