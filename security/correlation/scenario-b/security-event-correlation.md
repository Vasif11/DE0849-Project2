# Scenario B - Security Event Correlation

- Run ID: `20261024-113816`
- Generated: 2026-10-24T11:40:36
- Target: 10.20.10.20:3000
- Controlled signature: `/rest/products/search?q=%27%28`

## Independent observations

| Layer | Tool | Result |
|---|---|---|
| Application security | OWASP ZAP (alert 40018) | 1 SQL Injection finding(s) |
| Runtime / browser | Selenium | login_success = yes (registered-user) |
| Network traffic | PCAP | 105 packets, SQLi request present = yes |
| Network detection | Suricata (SID 1000001) | 1 event(s) |

## Correlation result

- Application-security detection (ZAP 40018): **yes**
- Controlled traffic captured in PCAP: **yes**
- Network detection (Suricata SID 1000001): **yes**
- Runtime authentication validated (Selenium): **yes**

### Status: **CORRELATED**

Chain: controlled SQLi activity -> ZAP application-security finding -> captured PCAP -> Suricata network detection -> correlation -> CI/CD security decision.

> Note: the ZAP targeted test sends `POST /rest/user/login`, while the controlled network positive control sends `GET /rest/products/search?q=%27%28`. These are different HTTP transactions associated with the same run; they are not presented as a packet-level match.
