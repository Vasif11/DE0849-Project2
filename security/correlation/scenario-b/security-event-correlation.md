# Scenario B - Security Event Correlation

- Run ID: `20261023-220309`
- Generated: 2026-10-23T22:06:44
- Target: 10.20.10.20:3000
- Controlled signature: `/rest/products/search?q=%27%28`

## Independent observations

| Layer | Tool | Result |
|---|---|---|
| Application security | OWASP ZAP (alert 40018) | 0 SQL Injection finding(s) |
| Runtime / browser | Selenium | login_success = NO (None) |
| Network traffic | PCAP | 54 packets, SQLi request present = yes |
| Network detection | Suricata (SID 1000001) | 0 event(s) |

## Correlation result

- Application-security detection (ZAP 40018): **NO**
- Controlled traffic captured in PCAP: **yes**
- Network detection (Suricata SID 1000001): **NO**
- Runtime authentication validated (Selenium): **NO**

### Status: **NOT_CORRELATED**

Chain: controlled SQLi activity -> ZAP application-security finding -> captured PCAP -> Suricata network detection -> correlation -> CI/CD security decision.

> Note: the ZAP targeted test sends `POST /rest/user/login`, while the controlled network positive control sends `GET /rest/products/search?q=%27%28`. These are different HTTP transactions associated with the same run; they are not presented as a packet-level match.
