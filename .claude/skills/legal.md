# Indian & Global Regulatory Compliance — Single Source of Truth

> This file contains ALL checks across 7 regulatory frameworks. The compliance engine reads this and auto-detects which frameworks apply based on the codebase.

---

## 🇮🇳 DPDP Act 2023 (Digital Personal Data Protection)

| # | Check | What to Detect in Code | Section | Penalty |
|---|-------|----------------------|---------|---------|
| D1 | No consent before data collection | Forms/APIs collecting data without consent UI | Sec 6 | Up to ₹250 Cr |
| D2 | No privacy policy | Missing `/privacy`, `/privacy-policy`, `/terms` routes or pages | Sec 5 | Up to ₹250 Cr |
| D3 | Children's data without age gate | No age verification before collecting minor's data | Sec 9 | Up to ₹200 Cr |
| D4 | No data erasure mechanism | No delete account / erase data endpoint | Sec 12(3) | Up to ₹250 Cr |
| D5 | No consent withdrawal | No UI/API to revoke previously given consent | Sec 6(6) | Up to ₹250 Cr |
| D6 | Excessive data collection | Collecting data beyond stated purpose | Sec 4(2) | Up to ₹250 Cr |
| D7 | No grievance redressal | No complaint mechanism for data principals | Sec 13 | Up to ₹250 Cr |
| D8 | Bundled consent | Single checkbox for multiple data processing purposes | Sec 6 | Up to ₹250 Cr |
| D9 | No breach notification | No incident response / notification workflow | Sec 8(6) | Up to ₹250 Cr |
| D10 | Cross-border transfer without check | Data sent to servers outside India without adequacy | Sec 16 | Up to ₹250 Cr |

### DPDP Code Patterns
```
# Violation: Form without consent
<form action="/signup" method="POST">  <!-- No consent checkbox before submit -->

# Violation: Pre-ticked consent
<input type="checkbox" checked={true} />  <!-- Consent not freely given -->
<input type="checkbox" checked="checked" />

# Violation: Data collection before consent
document.cookie = "tracking=1";  <!-- Set before consent banner interaction -->
analytics.track("pageview");  <!-- Tracking before consent -->

# Violation: Bundled consent
<input type="checkbox" id="consent" /> I agree to all terms  <!-- Single checkbox for everything -->

# Violation: No withdrawal
<!-- No UI element to revoke consent, no /revoke-consent endpoint -->

# Violation: No age gate
<!-- Signup form without date of birth or age verification step -->

# Fix: Proper consent
<input type="checkbox" id="marketing-consent" /> Marketing emails
<input type="checkbox" id="analytics-consent" /> Analytics tracking
<!-- Each purpose has its own unchecked checkbox -->
```

---

## 🇮🇳 IT Act 2000 (Information Technology Act)

| # | Check | What to Detect | Section | Penalty |
|---|-------|---------------|---------|---------|
| IT1 | No published privacy policy | Website/app lacks accessible privacy policy page | Sec 43A + SPDI Rules | Compensation liability |
| IT2 | SPDI without reasonable security | Sensitive data stored without encryption/RBAC | Sec 43A | Compensation for wrongful loss |
| IT3 | No consent for SPDI collection | Collecting sensitive data without consent | SPDI Rules Rule 5 | Sec 43A liability |
| IT4 | Unauthorized disclosure risk | PII access without access controls | Sec 72A | 3 years + ₹5 lakh fine |
| IT5 | No data transfer safeguards | Sharing data with third parties unprotected | SPDI Rules Rule 7 | Sec 43A liability |
| IT6 | No user review mechanism | No option for users to review/correct data | SPDI Rules Rule 5(6) | Compliance gap |
| IT7 | Purpose limitation violation | Data used beyond stated purpose | SPDI Rules Rule 5(4) | Sec 43A liability |
| IT8 | ISO 27001 gap indicators | No evidence of security standards | Sec 43A benchmark | Audit risk |

### SPDI Categories (IT Act)
Sensitive Personal Data or Information includes:
- Passwords
- Financial information (bank account, card, transaction)
- Health/medical data
- Sexual orientation
- Biometric information
- Any detail relating to the above provided for services

---

## 💳 PCI DSS 4.0 (Payment Card Industry)

**Auto-detect trigger:** Stripe, Razorpay, PayU, PayPal imports; card number patterns; payment-related code.

| # | Check | What to Detect | Requirement | Risk |
|---|-------|---------------|-------------|------|
| PCI1 | Card data in plaintext | Credit/debit card numbers stored unencrypted | Req 3 | Fines up to $500K/month |
| PCI2 | No TLS for card transmission | Payment data sent over HTTP | Req 4 | Data interception |
| PCI3 | Hardcoded payment credentials | Stripe/Razorpay/PayU keys in source | Req 2, 8 | Credential exposure |
| PCI4 | No access control on payment data | Payment endpoints without auth middleware | Req 7 | Unauthorized access |
| PCI5 | No MFA on admin/payment panels | Admin routes without 2FA | Req 8.4 | Brute force risk |
| PCI6 | No audit logging for payments | Payment transactions not logged | Req 10 | No forensic trail |
| PCI7 | No vulnerability scanning | No SAST/DAST in payment flow | Req 11 | Compliance gap |
| PCI8 | Default credentials | `admin/admin`, `test/test` in prod config | Req 2 | Instant compromise |
| PCI9 | No SBOM for payment deps | Third-party payment libs not tracked | Req 6 | Supply chain risk |

### PCI Code Patterns
```
# Violation: Card data in plaintext
db.execute("INSERT INTO orders (card_number) VALUES (?)", card_num)
# card_number column not encrypted

# Violation: Payment over HTTP
fetch("http://api.example.com/charge", { body: { card: cardNumber } })

# Violation: Hardcoded keys
STRIPE_SECRET_KEY = "sk_live_51H..."
RAZORPAY_KEY_SECRET = "rzp_live_..."

# Fix: Use tokenization
stripe.tokens.create({ card: { number, exp_month, exp_year, cvc } })
# Never store raw card — use Stripe/Razorpay tokens
```

---

## 🛡️ CERT-IN Guidelines 2025

**Always applicable for Indian digital businesses.**

| # | Check | What to Detect | Requirement | Penalty |
|---|-------|---------------|-------------|---------|
| CI1 | Logs retained <180 days | Log rotation config deleting before 180 days | Mandatory | Legal action under IT Act 70B |
| CI2 | No MFA for remote access | VPN/admin/cloud access without 2FA | Mandatory 2025 | Non-compliance penalty |
| CI3 | Shared accounts | Generic/shared login credentials in configs | Prohibited | Audit failure |
| CI4 | No incident reporting mechanism | No 6-hour incident notification workflow | Mandatory since 2022 | Financial penalties |
| CI5 | Logs not stored in India | Cloud logging to non-Indian regions | Mandatory | Non-compliance |
| CI6 | No SBOM | No software bill of materials | Mandatory for audits | Audit failure |
| CI7 | No annual security audit evidence | No VAPT/audit reports or configs | Mandatory annual | Debarment from govt contracts |
| CI8 | NTP not synchronized | Server time not synced with Indian NTP | Mandatory | Forensic evidence gap |

### CERT-IN Code Patterns
```
# Violation: Short log retention
logRotation: '30d'       # Must be >= 180 days
maxAge: '60d'            # Must be >= 180 days
rotate 4                 # If weekly = 28 days, too short

# Violation: Shared credentials
SERVICE_ACCOUNT = "shared_admin"
TEAM_API_KEY = "key_for_everyone"

# Violation: No MFA
# Admin login with password only, no TOTP/OTP step

# Fix: Log retention
logRotation: '180d'
maxAge: '180d'
rotate 26  # Weekly = 182 days
```

---

## 🏦 RBI Cyber Resilience Framework

**Auto-detect trigger:** Payment/banking/UPI/NEFT/RTGS code, PSO licenses.

| # | Check | What to Detect | Requirement | Applicability |
|---|-------|---------------|-------------|---------------|
| RBI1 | No device binding | Payment app without device fingerprint | Mobile Security | Payment apps |
| RBI2 | No root/jailbreak detection | No check for rooted/jailbroken devices | Mobile Security | Payment apps |
| RBI3 | No app integrity check | No checksum/signature validation | Mobile Security | Payment apps |
| RBI4 | Screen capture not blocked | Payment screens not screenshot-protected | Mobile Security | Payment apps |
| RBI5 | No tokenization of card data | Raw card numbers transmitted/stored | Data Security | All payment entities |
| RBI6 | API security gaps | Payment APIs without rate limiting/auth | ASLC requirement | All PSOs |
| RBI7 | No CISO designation | No security leadership role in config | Governance | Large/Medium PSOs |
| RBI8 | No risk assessment before launch | New features without security review | Risk Mgmt | All PSOs |

---

## 📈 SEBI CSCRF

**Auto-detect trigger:** Stock/trading APIs, portfolio management, market data, broker code.

| # | Check | What to Detect | Requirement | Applicability |
|---|-------|---------------|-------------|---------------|
| SB1 | No data classification | Financial data not classified | Identification | All SEBI REs |
| SB2 | No encryption at rest | DB/file storage without encryption | Protection | All SEBI REs |
| SB3 | No API security controls | Trading APIs without auth/rate limiting | Protection | MIIs, Qualified REs |
| SB4 | No SOC/monitoring | No security monitoring or alerting | Detection | MIIs, Qualified REs |
| SB5 | No SBOM for dependencies | No software composition tracking | Supply Chain | All SEBI REs |
| SB6 | No VAPT evidence | No vulnerability assessment configs | Audit | All SEBI REs |
| SB7 | Post-quantum risk not assessed | Crypto not future-proofed | Identification | MIIs |

---

## 🏥 IRDAI Cyber Security 2023

**Auto-detect trigger:** Insurance policy/claims code, health data processing, actuarial systems.

| # | Check | What to Detect | Requirement | Applicability |
|---|-------|---------------|-------------|---------------|
| IR1 | Policyholder data unencrypted | Insurance/health data in plaintext | Data-Centric Security | All insurers |
| IR2 | Logs retained <180 days | App logs rotated before 180 days | Log Retention | All insurers |
| IR3 | No NTP synchronization | Server time not synced with Indian NTP | Time Sync | All insurers |
| IR4 | No 6-hour incident reporting | No breach notification workflow | Incident Response | All insurers |
| IR5 | No CISO role | No security officer designation | Governance | All insurers |
| IR6 | No quarterly security reports | No audit/review mechanism config | Board Reporting | All insurers |
| IR7 | No annual VAPT | No security testing evidence | Audit Requirement | All insurers |

---

## Compliance Violation → Code Pattern Quick Reference

| Code Pattern Found | Violation | Law/Regulation | Fix |
|-------------------|-----------|---------------|-----|
| Form submit without consent checkbox | Data collection without consent | DPDP Sec 6 | Add consent checkbox + store consent record |
| No `/privacy-policy` route | No privacy notice | DPDP Sec 5 + IT Act 43A | Create and publish privacy policy page |
| `document.cookie` set before consent | Tracking without consent | DPDP Sec 6 | Add cookie consent banner, defer tracking |
| Pre-ticked `checked={true}` | Invalid consent | DPDP Sec 6 | Remove `checked` default, require active opt-in |
| No age verification on signup | Children's data risk | DPDP Sec 9 | Add age gate + parental consent flow |
| `DELETE /user/:id` missing | No data erasure | DPDP Sec 12(3) | Implement account deletion API |
| PII in `console.log()` | Sensitive data in logs | CERT-IN + DPDP | Mask/redact PII before logging |
| `logRotation: '30d'` | Logs <180 days | CERT-IN | Set retention to minimum 180 days |
| Payment data over HTTP | Card data unencrypted in transit | PCI DSS Req 4 | Enforce HTTPS/TLS |
| `password` stored plaintext | No hashing | IT Act 43A + PCI DSS 3 | Use bcrypt/argon2 |
| No `X-Frame-Options` header | Clickjacking | OWASP A05 + CERT-IN | Add security headers |
| `cors: { origin: '*' }` | Unrestricted CORS | OWASP A05 + CERT-IN | Whitelist origins |
| No rate limiting on login | Brute force | PCI DSS 8 + RBI | Add rate limiter |
| `admin:admin` in config | Default creds | PCI DSS 2 + CERT-IN | Enforce strong passwords |
| Firebase `".read": true` | Open database | OWASP A01 + DPDP 8 | Restrict to authenticated |
| No `2FA`/`MFA` implementation | No multi-factor auth | CERT-IN 2025 + PCI DSS 8.4 | Implement TOTP/SMS 2FA |
| Shared service account credentials | Shared accounts | CERT-IN | Create individual accounts |
| No breach notification workflow | No incident response | DPDP 8(6) + CERT-IN | Implement 6-hour pipeline |
| Data transfer to foreign servers | Cross-border transfer | DPDP Sec 16 | Add data residency controls |
