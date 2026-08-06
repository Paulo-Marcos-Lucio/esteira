<p align="center"><a href="SECURITY.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/esteira/main/assets/btn-lang-pt.svg" alt="Ler este documento em Português" width="300"/></a></p>

# Security Policy

Report vulnerabilities **privately** to **contatopml26@gmail.com** (subject prefixed with `[security]`). Allow a reasonable amount of time for a fix before disclosing.

## Scope

Esteira is a **defensive**, **static** tool: it reads GitHub Actions workflow files and flags insecure configurations so they can be fixed. It **does not** execute the workflow, make network requests, authenticate anywhere, or modify the audited repository — the fix is *suggested* in the report, never applied.

The following are considered vulnerabilities in this project, among others:

- **False negative**: a demonstrably vulnerable workflow that the tool reports as clean.
- **False positive** that fails a correct pipeline.
- **Denial of service against the tool itself**: input (a workflow file) that causes the scan to hang or consume unbounded memory — the threat model includes running in CI over files that a third-party PR can modify.
- **Leak in the report**: a target's secret exposed in JSON/SARIF/console output beyond what's necessary to identify the finding.

## Legal Framework (Brazil)

Auditing a third party's pipeline **without written authorization** is a crime in Brazil. The tool is static and local — it never touches the target's environment — but any material you use as input (workflows, logs, artifacts) must be obtained lawfully.

- **Law 12.737/2012** (Carolina Dieckmann Law) and **Law 14.155/2021**: unauthorized access to another person's computing device, with aggravated penalties when private-communications content, trade secrets, or remote control are obtained.
- **Law 12.965/2014** (Marco Civil da Internet): retention and confidentiality of records and private communications.
- **Law 13.709/2018** — LGPD (Brazil's data-protection law, GDPR-equivalent): if the report contains personal data, you are a data processing agent and are liable for it.

Use Esteira on pipelines that you maintain or have **formal authorization, with a defined scope and period,** to review. Keep that authorization on file.
