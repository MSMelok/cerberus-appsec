# Aegis Web Scanner 🛡️

An AI-driven, consent-based web security scanner designed to help organizations and site owners eliminate critical web vulnerabilities, logic flaws, and zero-day risks before exploitation.

---

## 🎯 Mission & Vision

Modern AppSec tools often produce excessive false positives or miss complex, multi-step business logic flaws. Drawing from hands-on offensive security experience in **Anthropic's Cyber Verification Program (CVP)** and active vulnerability disclosure on **HackerOne**, this project aims to bridge the gap between automated scanning and human-level security analysis.

*   **Consent-First Architecture:** Scans only run against target environments with explicit authorization and verified ownership.
*   **High Accuracy Focus:** Combines static/dynamic analysis with LLM-assisted verification to achieve high signal-to-noise detection.
*   **Systemic Attack Prevention:** Designed with real-world threat vectors in mind to prevent wide-scale automated web exploits.

---

## 🏗️ Architecture & Tech Stack

| Layer | Technology / Tool | Purpose |
| :--- | :--- | :--- |
| **Core Scanner Engine** | Python / Go | High-performance async HTTP crawling & AST parsing |
| **AI / Reasoner** | Anthropic Claude API / Local SLMs | Vulnerability triage, logic flow mapping, false-positive reduction |
| **Vulnerability Knowledgebase** | Nuclei Templates / Semgrep / Custom Rules | Deterministic pattern matching & known CVE checks |
| **Data & Queue** | PostgreSQL / Redis | Scan state management, task distribution, and audit logs |
| **Reporting & CLI** | Python (Rich / Typer) | Structured markdown report generation & terminal output |

---

## 🗺️ Development Roadmap

### Phase 1: Core Engine & Verification (Current)
* [ ] Implement async web crawler with scope & domain ownership validation.
* [ ] Integrate deterministic vulnerability rule engine (headers, injection vectors, CSRF, misconfigurations).
* [ ] Build AST parsing pipeline for common web backend code structures.

### Phase 2: AI Triage & Reasoner Integration
* [ ] Connect LLM layer to evaluate scan results and simulate attack paths ethically.
* [ ] Implement automated false-positive filtering logic.
* [ ] Develop standardized security advisory output with context-aware remediation steps.

### Phase 3: Reporting & Community Release
* [ ] Export options (JSON, SARIF, Markdown advisories).
* [ ] Open-source initial rulesets and scanner modules.
* [ ] Continuous alignment with emerging CVP research patterns.

---

## 🔒 Ethics & Authorization

This tool is strictly designed for **defensive security testing and authorized security assessments**. It requires explicit consent from domain owners prior to initiating active scans. Unsanctioned scanning against third-party systems is explicitly unsupported.

---

## 🤝 Contributing & Contact

Created as part of ongoing security research and participation in the **Anthropic Cyber Verification Program (CVP)** and **HackerOne**. 

*   **Issues:** For bug reports or feature requests, please open a GitHub Issue.
*   **Responsible Disclosure:** For vulnerability reports regarding this scanner itself, please see `SECURITY.md`.
