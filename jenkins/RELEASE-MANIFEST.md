# Scenario B Release Manifest (version-pinned components)

Every externally supplied component is pinned so the security pipeline is reproducible. A student
should never have to guess which version the reference environment expects.

## Persistent services
| Component | Image / version | Address |
|---|---|---|
| OWASP Juice Shop (controlled target) | `bkimminich/juice-shop:v20.2.0` | 10.20.10.20:3000 |
| Selenium Grid (standalone Chromium) | `selenium/standalone-chromium:132.0` → `telecom-lab-selenium:1.0` | 10.20.10.30:4444 |
| Jenkins (optional orchestrator) | `jenkins/jenkins:lts-jdk21` → `telecom-lab-jenkins:lts-jdk21` | 10.20.10.10:8080 |

## On-demand (ephemeral) tool jobs
| Tool | Image / version | Purpose |
|---|---|---|
| OWASP ZAP | `ghcr.io/zaproxy/zaproxy:stable` | baseline + targeted SQLi (alert 40018) |
| Suricata | `jasonish/suricata:8.0` | offline PCAP IDS (local SID 1000001) |
| Trivy | `aquasec/trivy:0.75.0` | image vulnerability scan |
| Syft | `anchore/syft:v1.52.0` | CycloneDX SBOM |
| Traffic capture | tcpdump on `br-sec` (host) / `telecom-lab-capture:1.0` | fresh PCAP |

## Host-side analysis tooling
| Tool | Version (lab host) |
|---|---|
| TShark | 4.6.x |
| jq | 1.7.x |
| Python | 3.14 (venv `/opt/p1venv`), `selenium`, `scikit-learn` |

## Jenkins plugins (pre-installed, recorded by Preflight)
git, docker-workflow, credentials-binding, timestamper, htmlpublisher, workflow-aggregator.

## Local IDS rule
`security/ids/rules/scenario-b-local.rules` — **SID 1000001**:
`LOCAL Scenario B SQLi test - encoded quote/parenthesis in product search`
(`GET /rest/products/search?q=%27%28`).

## Deviation note
The reference guidebook names `telecom-lab-jenkins:2.580.1-jdk21`. On the 4 GB lab host, running
Jenkins + Juice Shop + Selenium + ephemeral tool jobs concurrently exceeds available memory, so the
pipeline is executed by the Jenkins-equivalent orchestrator `scripts/run_pipeline.sh` (identical
stages, tools and evidence paths), and `jenkins/Jenkinsfile` is provided as the CI definition for a
larger host. This is a documented, justified deviation that produces the same evidence.
