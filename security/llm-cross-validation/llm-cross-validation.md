# LLM-Assisted Cross-Validation (Phase 2E)

Per the guidebook, LLMs are used **as assistance and a cross-validation tool, not as the
authoritative security detector or security gate**. For each task below the LLM conclusion is
recorded and then **independently verified against the original machine-generated artifacts**
(via `jq`/Python on the raw JSON), and any disagreement is stated. The deterministic ZAP, PCAP,
Suricata, Trivy and Syft outputs remain the source of truth.

- **Model / provider / version:** Claude Opus 4.8 (`claude-opus-4-8`), Anthropic.
- **Analysis date:** 2026-10-24.
- **Run:** `RUN_ID=20261024-113816` (Security Gate PASS in REPORT_ONLY).
- **Verification method:** queries over the committed artifacts under `security/` (see commands in each task).

---

## Task 1 (required) - SBOM vs vulnerability-scanning evidence

**Prompt summary.** "Given the Trivy image vulnerability report and the Syft CycloneDX SBOM for
`bkimminich/juice-shop:v20.2.0`, summarise the vulnerability posture, and determine whether the
SBOM provides traceability for the HIGH/CRITICAL findings (i.e. are the vulnerable packages present
in the component inventory?). State clearly what the SBOM does and does not prove."

**Input evidence.**
- `security/scans/trivy-ci/juice-shop-v20.2.0.json`
- `security/sbom-ci/juice-shop-v20.2.0.cdx.json`

**LLM conclusion (Claude Opus 4.8).**
The Juice Shop image carries a substantial vulnerability load: on the order of a dozen CRITICAL and
several dozen HIGH findings, concentrated in a relatively small set of vulnerable npm packages
(e.g. `crypto-js`, `handlebars`, `jsonwebtoken`, `decompress`). The SBOM is a much larger inventory
(a few thousand components) and should list the vulnerable packages, giving traceability from a CVE
to a specific component. The SBOM itself does **not** establish exploitability or that the image is
insecure/secure - it is an inventory; Trivy supplies the vulnerability verdict, and the two are
complementary.

**Independently verified conclusion (against the raw artifacts).**
```
# severity counts (Trivy)
jq '[.Results[]?.Vulnerabilities[]?.Severity]|group_by(.)|map({sev:.[0],n:length})' trivy.json
  -> CRITICAL 12, HIGH 54, MEDIUM 89, LOW 24
# distinct HIGH/CRITICAL packages
  -> 25 packages (crypto-js, handlebars, jsonwebtoken, decompress, engine.io, express-jwt, ...)
# SBOM size
jq '.components|length' sbom.cdx.json   -> 2677
# traceability check (Python): are all 25 vulnerable packages present in the SBOM by name?
  -> present in SBOM: 25 / 25   (missing: 0)
```
**Verified:** the counts (12 CRITICAL / 54 HIGH) match, and **all 25 HIGH/CRITICAL vulnerable
packages are present in the SBOM by exact name (0 missing)** - so the SBOM does provide full
traceability for the Trivy HIGH/CRITICAL findings.

**Disagreement:** none on the numbers. One nuance the LLM was right to flag and which the evidence
confirms: the SBOM's 2677 components vastly exceed the 25 vulnerable packages - most components have
no HIGH/CRITICAL CVE, so **"the SBOM lists 2677 components" must not be read as "2677 risks."** The
SBOM is inventory/traceability; Trivy is the vulnerability verdict. Example CRITICAL confirmed in the
raw report: `crypto-js 3.3.0` / `CVE-2023-46233` (fixed in 4.2.0). The LLM claim was accepted only
after this verification.

---

## Task 2 - Correlation claim: is the Suricata detection the same transaction as the ZAP finding?

**Prompt summary.** "The correlation report says the controlled SQLi activity is CORRELATED across
the application-security (ZAP alert 40018) and network-detection (Suricata SID 1000001) layers. Does
this mean the Suricata-detected packet is the same HTTP transaction that ZAP flagged? Verify the
actual request each tool observed and judge whether a packet-level identity is being claimed."

**Input evidence.**
- `security/reports/zap/scenario-b-ci-targeted/scenario-b-ci-targeted.json` (+ `-sqli-summary.json`)
- `security/ids/scenario-b/ci/eve.json` (Suricata)
- `security/traffic/scenario-b/ci/juice-shop-ci-sqli.pcapng`
- `security/correlation/scenario-b/security-event-correlation.json`

**LLM conclusion (Claude Opus 4.8).**
`CORRELATED` should be interpreted as a **common-run association**: the same controlled test run
produced an application-security finding (ZAP 40018) and a network detection (Suricata SID 1000001)
against the same target endpoint. It is **not** a packet-level identity claim. In fact the two tools
observed *different* HTTP transactions: the deterministic network positive control is
`GET /rest/products/search?q=%27%28`, whereas ZAP's active scanner injected its own payloads (e.g.
`q=apple'`). Both target `/rest/products/search` parameter `q`, but presenting the captured GET as
the packet-level trace of the ZAP finding would be incorrect.

**Independently verified conclusion (against the raw artifacts).**
```
# Suricata SID 1000001 event
  -> src 10.20.10.1 -> dest 10.20.10.20:3000  uri /rest/products/search?q=%27%28
# ZAP alert 40018 instance
  -> url http://10.20.10.20:3000/rest/products/search?q=apple'  param q  attack apple'  risk High
```
**Verified:** both observations are on `10.20.10.20:3000` `/rest/products/search` parameter `q`
(same endpoint, same run), but the **payloads differ** (`%27%28` vs `apple'`) - they are **distinct
HTTP transactions**. The correlation report already encodes this caveat in its own `note` field, so
the machine artifact and the LLM interpretation agree.

**Disagreement:** none between the LLM and the evidence. The cross-validation specifically guards
against a plausible *wrong* LLM claim - "Suricata captured the exact ZAP SQL-injection request" -
which the raw artifacts refute. The correct, verified statement is a same-run, same-endpoint
association across two detection layers, consistent with the guidebook's explicit warning that the
ZAP login request and the captured search request are different transactions.

---

## Summary

| Task | LLM conclusion | Verified against artifacts | Disagreement |
|---|---|---|---|
| 1 SBOM vs Trivy | 12 CRIT/54 HIGH in a small package set; SBOM gives traceability, not a verdict | 12 CRIT / 54 HIGH; 25/25 vulnerable packages present in SBOM | none (nuance confirmed: inventory ≠ risk count) |
| 2 Correlation claim | CORRELATED = common-run association, not a packet-level match | same endpoint/run, different payloads (`%27%28` vs `apple'`) | none (guards against the wrong "same transaction" claim) |

In both tasks the LLM output was treated as a hypothesis and accepted only after verification against
the deterministic machine-generated evidence. No vulnerability finding, IDS detection, correlation
claim or gate decision in this project rests on the LLM alone.
