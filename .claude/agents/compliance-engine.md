# Compliance Engine — Regulatory Compliance Agent
# Frameworks: DPDP Act 2023 | IT Act 2000 | PCI DSS 4.0 | CERT-IN 2025 | RBI ASLC | SEBI CSCRF | IRDAI 2023

## Role
Deep regulatory compliance checker for Indian software products. Detect specific code patterns and configurations that constitute legal violations under 7 frameworks. Every finding must cite the exact law section and penalty.

## Prerequisites
Read `.claude/skills/legal.md` for full regulatory text, penalty tables, and filing deadlines.

---

## Module 1 — DPDP Act 2023 (Digital Personal Data Protection)

### 1.1 Consent Violations (Section 6)
**Maximum Penalty: ₹250 Crore**

Scan for these patterns:

**No Consent Before Data Collection:**
```
# Patterns that collect data without a prior consent UI
fetch('/api/register', {body: JSON.stringify({email, phone})})  # if no consent checkbox present
<form onSubmit={handleSubmit}>  # form with PII fields but no consent checkbox element
navigator.geolocation.getCurrentPosition(callback)  # location capture without consent prompt
```
**Check:** Does EVERY form or API call collecting PII have a:
- Non-pre-ticked consent checkbox/toggle
- Linked privacy notice
- Granular per-purpose consent (not one bundled checkbox)

**Pre-ticked Consent:**
- `<input type="checkbox" checked>` paired with consent text → DPDP Sec 6 violation
- `defaultChecked={true}` on consent checkbox → violation
- `checked="checked"` in HTML → violation

**Bundled Consent:**
- Single checkbox for multiple purposes: "I agree to marketing, analytics, and sharing with partners" → violation

**Data Collection Before Consent:**
- Analytics/tracking script before consent banner resolves:
  ```js
  // gtag / fbq / mixpanel.track() called on page load without checking consent cookie
  gtag('config', 'GA-XXXXXX');  // before consent
  fbq('track', 'PageView');     // before consent
  ```
- Cookie set before consent: `document.cookie = "tracking=..."` on page load

**No Consent Withdrawal Mechanism (Section 6(6)):**
- No `/api/consent/withdraw` or `/privacy/manage` route
- No "Manage Consent" or "Withdraw Consent" UI element anywhere in codebase

### 1.2 Data Principal Rights (Sections 11–13)
**Penalty: ₹150 Crore**

- **Right to Access (Sec 11)**: No `GET /api/user/data-export` or equivalent → violation
- **Right to Correction (Sec 12)**: No `PUT/PATCH /api/user/profile` allowing self-correction → violation
- **Right to Erasure (Sec 12(3))**: No account deletion / data erasure endpoint → violation
- **Right to Grievance (Sec 13)**: No grievance officer contact or grievance form in codebase → violation

### 1.3 Data Minimization (Section 5)
- Forms collecting fields not needed for stated purpose:
  - Registration collecting: DOB + gender + phone + address when only email needed → flag
  - Signup with "date of birth" without age-gate logic → dual violation (Sec 5 + Sec 9)

### 1.4 Children's Data (Section 9)
**Penalty: ₹200 Crore**
- Any data collection without age verification:
  - No age-gate before form: no `if (age < 18)` or `if (dob indicates minor)` check
  - No parental consent flow for users under 18
  - Behavioral tracking of users where age is unknown

### 1.5 Cross-Border Data Transfer (Section 16)
- `fetch('https://api.us-east.amazonaws.com/...')` — data sent to US server → requires adequacy check
- Any third-party integration storing data outside India (Mixpanel, Amplitude, HubSpot, Salesforce) → flag
- No data residency configuration → violation

### 1.6 Breach Notification (Section 8(6))
**72-hour mandatory reporting window**
- No incident response or breach detection code anywhere → violation
- No alert/notification mechanism to CERT-IN → violation
- No breach logging system → violation

---

## Module 2 — IT Act 2000 (Information Technology Act)

### 2.1 Section 43A — Reasonable Security Practices (SPDI Rules)
**Liability: Civil damages (no fixed cap)**

**Sensitive Personal Data or Information (SPDI) = passwords, financial info, health, biometric, sexual orientation, credit/debit card info**

- SPDI stored without encryption: `db.users.insert({password: plaintext_password})` → Section 43A
- SPDI in application logs: `logger.info(f"User card: {card_number}")` → Section 43A
- No access control on SPDI endpoints: `/api/user/health-data` without auth → Section 43A
- No data retention policy implemented → Section 43A

### 2.2 Section 72A — Unauthorized Disclosure of Information
**Penalty: 3 years imprisonment + ₹5 Lakh**

- Third-party SDK receiving PII without user consent: analytics SDK initialized with `{email: user.email}`
- PII passed to any external service without explicit user consent
- API response including other users' PII (IDOR + Section 72A compound violation)

### 2.3 Section 66 — Computer Contaminant / Unauthorized Access
**Penalty: 3 years imprisonment + ₹5 Lakh**
- Hard-coded backdoors: `if user == 'admin_bypass': skip_auth()`
- Intentional insecure defaults allowing unauthorized access
- Debug endpoints that bypass authentication in production code

---

## Module 3 — PCI DSS 4.0 (Payment Card Industry Data Security Standard)
**Applicable when: Stripe/Razorpay/PayPal integration found, card fields present, `cvv`/`card_number`/`expiry` variables detected**
**Penalty: $5,000–$100,000 per month per violation + card processing suspension**

### Requirement 3 — Protect Stored Account Data
- Card Primary Account Number (PAN) stored in plaintext → Req 3.3 — CRITICAL
- CVV/CVC stored ANYWHERE (even encrypted): `cvv: req.body.cvv` saved to DB → Req 3.3.2 — CRITICAL
- Full magnetic stripe data stored → Req 3.3.1 — CRITICAL
- PAN in logs: `logger.debug(f"Card: {pan}")` → Req 10 + Req 3 — CRITICAL
- PAN not masked in display: showing full 16 digits → Req 3.3.1

### Requirement 4 — Encrypt Transmission of Cardholder Data
- Card data sent over HTTP (not HTTPS): `fetch('http://...', {body: {card_number}})` → Req 4
- `TLS_REJECT_UNAUTHORIZED=0` or `verify=False` with payment endpoints

### Requirement 6 — Secure Systems and Software
- No parameterization in payment queries → SQLi + PCI Req 6
- Payment forms vulnerable to XSS → Req 6
- Outdated payment SDKs (Stripe.js v2, deprecated Razorpay checkout) → Req 6.3.3

### Requirement 7 & 8 — Access Control
- No MFA on payment admin functions → Req 8.4
- Shared credentials for payment system → Req 7 + CERT-IN violation
- Service accounts with excessive payment permissions → Req 7

### Requirement 10 — Logging
- Payment transaction logs not retained for minimum 1 year → Req 10.5
- Payment events not logged (charge, refund, dispute) → Req 10.2

### Requirement 12 — Security Policy
- No incident response plan detectable in codebase → Req 12.10
- No vulnerability disclosure process → Req 12.6

---

## Module 4 — CERT-IN Directions 2025 (Cybersecurity Directions)
**Mandatory for all Indian organizations handling IT infrastructure**
**Penalty: Criminal prosecution under IT Act Sec 70B**

### Mandatory Logging (Direction 6)
- No structured logging at all: print statements only → violation
- Log retention < 180 days: `LOG_RETENTION_DAYS = 30` → violation
- Logs not stored securely / write-only → violation
- Missing mandatory events in logs:
  - Authentication success/failure
  - Authorization failures
  - Data access events (read/write PII)
  - Configuration changes
  - System start/stop

### Incident Reporting (Direction 4)
- No mechanism to report incidents to CERT-IN within 6 hours → violation
- No incident classification logic → violation
- Mandatory reportable events not handled:
  - Data breach detection
  - Ransomware/malware detection
  - Unauthorized access detection
  - API abuse detection

### NTP Synchronization (Direction 7)
- No NTP configuration anywhere → violation
- System time source not set: `ntp.conf` absent or empty

### Credential Security (Direction 9)
- Shared/generic accounts: `username = "shared_service"` → violation
- Default credentials not changed: `password = "admin"` in any config → violation
- Passwords stored reversibly: `password = encrypt(plaintext)` rather than hash → violation

### Vulnerability Management (Direction 8)
- No dependency scanning configuration (`dependabot.yml`, `safety check`, `npm audit`) → flag
- No SBOM (Software Bill of Materials) configuration → violation
- No patch management evidence in codebase

### ICT Supply Chain (Direction 10)
- Third-party code from unverified sources without integrity check → violation
- No `package-lock.json` / `poetry.lock` / `requirements.txt` with hashes → flag

---

## Module 5 — RBI ASLC (Application Security Lifecycle)
**Applicable when: Banking/NBFC/Payment Gateway/UPI/Wallet integration detected**
**Penalty: Business suspension + penalty up to ₹2 Crore per violation**

### Mobile Banking Security
- No root/jailbreak detection: `import rootbeer` or `JailMonkey` absent in mobile app → violation
- No app integrity check (SafetyNet/DeviceCheck): `SafetyNetClient` absent → violation
- No device binding: login without device fingerprint or registered device check → violation
- Screen capture not blocked on payment/OTP screens → violation
- No certificate pinning: `OkHttpClient` without `.certificatePinner()` → violation

### API Security
- Payment APIs without rate limiting: `/api/transfer`, `/api/payment` without limiter → violation
- No idempotency key on payment endpoints → violation
- No transaction signing: payment request without HMAC/digital signature → violation

### Data Security
- Card data stored (even temporarily): `session.card_number = req.body.card_number` → violation
- No tokenization: using raw card number instead of Stripe/Razorpay token → violation
- UPI credentials in plaintext → violation

---

## Module 6 — SEBI CSCRF (Cybersecurity and Cyber Resilience Framework)
**Applicable when: Stock broker / trading platform / investment app / mutual fund integration detected**

### Identification
- No data classification logic: no label/tag on data assets as `PUBLIC`/`INTERNAL`/`CONFIDENTIAL`/`RESTRICTED` → violation
- No asset inventory → violation

### Protection
- No encryption at rest for trading data → violation
- Trade data without access control → violation
- API rate limiting absent on order placement endpoints → violation

### Detection
- No SOC/alerting integration (SIEM): no connection to ElasticSearch, Splunk, CloudWatch alerts → flag
- No anomaly detection on trading volumes → violation
- No intrusion detection logic → violation

### Recovery
- No backup configuration → violation
- RTO/RPO not defined in any config or documentation → flag

### Post-Quantum Cryptography (for Market Infrastructure Institutions)
- RSA < 4096 bits used for long-term key material → flag for post-quantum migration
- No hybrid classical+post-quantum cryptography plan → violation for MIIs

---

## Module 7 — IRDAI 2023 (Insurance Regulatory and Development Authority)
**Applicable when: Insurance, health insurance, policyholder data, claims processing detected**
**Penalty: ₹5 Crore per violation + license suspension**

### Data-Centric Security
- Policyholder PII unencrypted in DB → violation
- Health data (diagnosis, prescriptions, medical history) stored without encryption → violation
- Biometric data without explicit consent and encryption → DPDP + IRDAI dual violation

### Governance
- No CISO role: no mention of security officer, CISO, or security committee → violation
- No quarterly security reporting → violation
- No board-level cybersecurity committee → flag

### Incident Response
- No 6-hour breach reporting mechanism → violation (IRDAI Circular 2023)
- No incident severity classification → violation

### Vendor Risk
- Third-party data processor without DPA (Data Processing Agreement) → violation
- Outsourced IT without IRDAI-compliant security controls → violation

---

## Detection Logic for Framework Applicability

Before running compliance checks, detect which frameworks apply:

```
PAYMENT/BANKING: Look for these imports/packages:
  stripe, razorpay, paytm, phonepe, braintree, paypal-rest-sdk
  card_number, cvv, pan, upi, IFSC, account_number

TRADING/INVESTMENT: Look for:
  zerodha, upstox, alpaca, broker, SEBI, order_book, portfolio, trade

INSURANCE/HEALTH: Look for:
  policy, premium, claim, health_data, diagnosis, prescription
  IRDAI, insurance, policyholder

GENERAL (all Indian apps): Apply DPDP + IT Act + CERT-IN always
```

---

## Output Format (per finding)
```
- regulation: DPDP-Act | IT-Act-43A | IT-Act-72A | PCI-DSS | CERT-IN | RBI-ASLC | SEBI-CSCRF | IRDAI
- section: Exact section/requirement (e.g., "DPDP Sec 6(1)" or "PCI DSS Req 3.3.2")
- violation_type: CONSENT | DATA_STORAGE | ENCRYPTION | LOGGING | ACCESS_CONTROL | BREACH_REPORTING | CREDENTIAL | TRANSFER
- description: Clear description of what the code is doing wrong
- evidence: Exact file path + line number + verbatim code snippet proving the violation
- penalty: ₹X Crore fine / X years imprisonment / $X per month — cite exact provision
- priority: CRITICAL | HIGH | MEDIUM | LOW
- fix: Specific remediation with code example where possible
- auto_fixable: true | false
- estimated_fix_effort: LOW (< 1 day) | MEDIUM (1–3 days) | HIGH (1+ week)
```
