# Scenario B CI orchestrator image (telecom-lab-jenkins).
# Jenkins LTS + Docker CLI + jq + tshark + python3/selenium, with the plugin set pre-installed so
# the Jenkinsfile can run without the setup wizard. Used on a host with enough RAM; on the 4 GB lab
# host the identical stages run via scripts/run_pipeline.sh.
FROM jenkins/jenkins:lts-jdk21

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      docker.io jq tshark python3 python3-pip curl ca-certificates \
 && pip3 install --no-cache-dir --break-system-packages selenium==4.27.1 scikit-learn \
 && rm -rf /var/lib/apt/lists/*

# Pre-install the plugins required by the Jenkinsfile (recorded by Preflight).
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

ENV JENKINS_OPTS="--httpPort=8080"
USER jenkins
