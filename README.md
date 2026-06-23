# 🔐 Petpooja Claude Code Security & Compliance Agent

An advanced, zero-infrastructure security and regulatory compliance scanner built specifically for **Claude Code**.

By leveraging Claude's native reasoning capabilities and local file tools, this plugin acts as an automated triage layer. It performs:
- **SAST** — Static Application Security Testing
- **DAST Simulation** — Runtime API attack simulation
- **Secret Hunting** — Detects 30+ types of exposed credentials
- **Compliance Auditing** — Checks against 7 major Indian regulatory frameworks (DPDP Act, IT Act, PCI DSS, CERT-IN, RBI, SEBI, IRDAI)

No servers. No API keys. No background services. Just Claude.

---

## 🚀 How to Use This in Claude Code

> **The entire plugin is just a `.claude/` folder with markdown files.** When you copy it into your project and open Claude Code, your slash commands are automatically registered and ready.

### ✅ Step 1 — Install Git (if not already installed)
Make sure you have [Git installed](https://git-scm.com/downloads).

---

### ✅ Step 2 — Clone this repo into your project

Open a terminal in the **root of your project** and run:

**macOS / Linux:**
```bash
git clone https://github.com/TheWildEye/Petpooja-security.git _tmp_agent && cp -r _tmp_agent/.claude ./ && rm -rf _tmp_agent
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/TheWildEye/Petpooja-security.git _tmp_agent; Copy-Item -Recurse _tmp_agent/.claude ./ ; Remove-Item -Recurse -Force _tmp_agent
```

This will copy only the `.claude/` plugin folder into your project — nothing else.

---

### ✅ Step 3 — Open Claude Code in your project

```bash
claude
```

---

### ✅ Step 4 — Run a scan

Just type any of the registered slash commands:

| Command | What it does |
|---|---|
| `/security-assess` | Full scan: SAST + DAST simulation + Secret hunting + Compliance audit |
| `/compliance-audit` | Deep Indian regulatory audit (DPDP, IT Act, PCI DSS, CERT-IN, RBI, SEBI, IRDAI) |
| `/quick-scan` | Fast SAST + secret scan only (no DAST, no compliance) |
| `/fix-issue` | Interactively fix a specific vulnerability with before/after diff |

That's it. No `npm install`, no `pip install`, no API keys.

---

## 🔁 Updating the Plugin

To get the latest version of the plugin rules and engines, simply re-run the clone command from Step 2 in your project root. It will overwrite the `.claude/` folder with the latest version.

---

## ⚙️ Alternative: One-Line Install Scripts

If you prefer scripts over the manual clone:

**macOS & Linux:**
```bash
# Project-level (current directory only)
curl -fsSL https://raw.githubusercontent.com/TheWildEye/Petpooja-security/main/install.sh | bash

# Global installation (available in every project)
curl -fsSL https://raw.githubusercontent.com/TheWildEye/Petpooja-security/main/install.sh | bash -s -- --global
```

**Windows (PowerShell):**
```powershell
# Project-level
irm https://raw.githubusercontent.com/TheWildEye/Petpooja-security/main/install.ps1 | iex

# Global
$s = irm https://raw.githubusercontent.com/TheWildEye/Petpooja-security/main/install.ps1; & ([scriptblock]::Create($s)) -Global
```

---

## 📐 Architecture

```
your-project/
└── .claude/
    ├── commands/               # Slash command entry points
    │   ├── security-assess.md  ← /security-assess
    │   ├── compliance-audit.md ← /compliance-audit
    │   ├── quick-scan.md       ← /quick-scan
    │   └── fix-issue.md        ← /fix-issue
    ├── agents/                 # Specialized reasoning engines
    │   ├── sast-engine.md
    │   ├── secret-hunter.md
    │   ├── dast-engine.md
    │   ├── compliance-engine.md
    │   └── security-reviewer.md
    ├── skills/                 # Knowledge base
    │   ├── owasp-top10.md
    │   ├── mitre-cwe.md
    │   ├── mobile-security.md
    │   └── legal.md            ← All 7 Indian compliance frameworks
    └── settings.json           # Agent permissions & scan config
```

---

## 🔒 Security & Data Privacy

This plugin is designed with strict privacy controls baked in:

- **Local-only processing:** All scans run entirely on your machine using Claude Code's file tools. Nothing leaves your computer.
- **No data exfiltration:** The agents are explicitly instructed not to make external HTTP requests or transmit code, secrets, or findings anywhere.
- **Passive analysis only:** The plugin reads and reasons about code as text. It never executes or evaluates the code it scans.
- **Prompt injection defense:** If any file in your repository contains text attempting to hijack or override the agent (e.g., "ignore previous instructions"), it is flagged as a `CWE-77` security finding and the agent continues unaffected.

---

## 🔒 Auto-Fix Safety Tiers

| Tier | Risk | Auto-apply? | Example |
|---|---|---|---|
| Tier 0 | Zero-risk | ✅ Auto | Add security headers |
| Tier 1 | Low-risk config | ✅ Auto + notify | Remove debug mode |
| Tier 2 | Code changes | ⚠️ Show diff, confirm | Parameterize SQL queries |
| Tier 3 | Auth/crypto/business logic | ❌ Never auto | Rewrite JWT flow |

---

## 🎯 Test Cases

The `test-cases/` directory contains 16 deliberately vulnerable files to validate the scanner:

| Scenario | File |
|---|---|
| SQL Injection (CWE-89) | `test-sqli.py` |
| XSS (CWE-79) | `test-xss.js` |
| Command Injection (CWE-78) | `test-cmdi.py` |
| Insecure Deserialization (CWE-502) | `test-deserial.py` |
| SSRF (CWE-918) | `test-ssrf.py` |
| Weak JWT (CWE-347) | `test-jwt.js` |
| Open CORS | `test-cors-open.js` |
| Prompt Injection | `test-prompt-inject.py` |
| Exposed Secrets | `test-secrets.env` |
| DPDP Missing Consent | `test-no-consent.html` |
| Pre-ticked consent | `test-preticked.html` |
| No Privacy Route | `test-no-privacy.py` |
| No Age Gate | `test-no-age-gate.js` |
| Plaintext Card Storage | `test-plaintext-card.py` |
| Short Log Retention | `test-short-logs.yaml` |
| Shared Credentials | `test-shared-creds.env` |

---

## 📋 Regulatory Frameworks Covered

| Framework | Scope |
|---|---|
| 🇮🇳 DPDP Act 2023 | Indian personal data protection (up to ₹250 Cr penalty) |
| 🇮🇳 IT Act 2000 | IT security, SPDI rules, unauthorized disclosure |
| 💳 PCI DSS 4.0 | Payment card data security |
| 🛡️ CERT-IN 2025 | Indian CERT mandatory cybersecurity guidelines |
| 🏦 RBI Cyber Framework | Payment & banking app security |
| 📈 SEBI CSCRF | Financial trading platform security |
| 🏥 IRDAI 2023 | Insurance and health data security |

---

## 🏗️ Built at Petpooja

For suggestions or feedback, contact:
- Vyom Nagpal — vyom.nagpal@petpooja.com
- Sahil Patel — sahil.patel@petpooja.com
