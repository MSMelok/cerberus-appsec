# Cerberus AppSec 🛡️🐕

An AI-driven, consent-first web application security scanner designed to detect complex logic flaws, eliminate zero-day risks, and reduce false positives through intelligent multi-layered analysis.

---

## 🎯 Mission & Vision

Modern AppSec tools often produce excessive false positives or miss multi-step business logic flaws. Named after the legendary three-headed guardian, **Cerberus AppSec** combines deterministic scanning, dynamic crawling, and LLM-assisted verification to bridge the gap between automated tools and human-level security testing.

Drawing from active offensive security experience in **Anthropic's Cyber Verification Program (CVP)** and vulnerability research on **HackerOne**, this project aims to protect critical web infrastructure from systemic threats before exploitation occurs.

* **Consent-First Architecture:** Active scans are strictly locked until explicit domain authorization/ownership is verified.
* **Multi-Layered Defense:** Integrates rule-based dynamic detection with AI-driven attack path modeling.
* **Signal-over-Noise Focus:** Built to filter out trivial false positives (%99.9 safety focus) so security teams can focus on true critical vectors.

---

## 🏗️ Architecture & Tech Stack

| Layer | Technology / Tool | Purpose |
| :--- | :--- | :--- |
| **CLI / Controller** | Python (`Typer`, `Rich`) | High-performance, interactive terminal application |
| **Crawler Engine** | Async Python (`httpx`, `asyncio`) | Asynchronous crawling, link extraction, and target scope isolation |
| **Rule Engine** | Dynamic Plugins (`Pydantic`) | Deterministic vulnerability checks (Headers, CSRF, Injection, Misconfigurations) |
| **AI Reasoner** | Anthropic Claude API / Local Models | Vulnerability triage, logic flow assessment, and false-positive filtering |
| **Data & State** | PostgreSQL / Redis / SQLite | Scan state management, session handling, and audit logs |

---

## 🗺️ Project Roadmap

### Phase 1: Core Async Engine & Base Rules (Current)
* [x] Lightweight CLI architecture and environment setup.
* [ ] Async HTTP crawler with strict scope and sub-domain isolation.
* [ ] Plugin architecture for standard vulnerability rules (headers, leak checks, known CVE patterns).

### Phase 2: Domain Authorization & Verification
* [ ] Implement domain-ownership verification mechanisms (DNS TXT record / HTTP upload challenge).
* [ ] Build scope enforcement to prevent unauthorized active testing.

### Phase 3: AI Triage & Reasoner Integration
* [ ] Integrate Claude API for analyzing complex response payloads and potential zero-day attack vectors.
* [ ] Automated context-aware remediation output and false-positive reduction pipeline.

---

## 🔒 Ethics & Authorization

This software is strictly intended for **defensive security assessments and authorized testing**. Cerberus AppSec requires explicit verification of domain ownership prior to executing active scans against target environments. Unsanctioned scanning against third-party systems is explicitly prohibited and unsupported.

---

## 🤝 Research & Context

Developed as part of ongoing web security research and active participation in the **Anthropic Cyber Verification Program (CVP)** and **HackerOne**.

* **Issues & Feature Requests:** Please submit a GitHub Issue.
* **Responsible Disclosure:** For vulnerability disclosures regarding Cerberus AppSec itself, please see `SECURITY.md`.
