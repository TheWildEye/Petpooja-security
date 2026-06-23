# OWASP Top 10 — 2021 Edition Checklist

## A01:2021 — Broken Access Control
**What to look for:**
- Missing access control checks on endpoints (no `@login_required`, no auth middleware)
- IDOR: Direct object references without ownership validation (`/users/:id` without checking `user == requester`)
- Path traversal: `open(user_input)`, `fs.readFile(req.params.path)` without sanitization
- Unsafe redirects: `redirect(request.args['url'])` without whitelist
- CORS misconfiguration allowing unauthorized origins
- Missing function-level access control (regular user accessing admin endpoints)
- Metadata manipulation (JWT claims, hidden fields, cookies)
- Force browsing to authenticated pages without session

**CWEs:** CWE-200, CWE-201, CWE-352, CWE-639, CWE-22, CWE-601, CWE-862, CWE-863

## A02:2021 — Cryptographic Failures
**What to look for:**
- Data transmitted in cleartext (HTTP, FTP, SMTP without TLS)
- Weak algorithms: MD5, SHA1 for passwords; DES, 3DES, RC4; ECB mode
- Key size < 256 bits AES, < 2048 bits RSA
- Hardcoded encryption keys or secrets in source code
- Missing encryption for sensitive data at rest (PII, financial, health)
- Weak key generation / no salt in password hashing
- Deprecated hash functions: `hashlib.md5()`, `crypto.createHash('sha1')`
- Self-signed certificates in production
- Insufficient entropy in random number generation for crypto

**CWEs:** CWE-259, CWE-327, CWE-331, CWE-321, CWE-311, CWE-312, CWE-319, CWE-798

## A03:2021 — Injection
**What to look for:**
- SQL: String concatenation in queries, f-strings, template literals with user input
- Command: `os.system()`, `subprocess.call(shell=True)`, `exec()`, `eval()`, `child_process.exec()`
- XSS: `innerHTML`, `dangerouslySetInnerHTML`, `document.write()`, `|safe` filter, unescaped output
- LDAP: User input in LDAP queries without escaping
- XPath: User input in XPath expressions
- NoSQL: `$where`, `$gt`, `$ne` operators with user input in MongoDB
- ORM: Raw queries with string interpolation even in ORM frameworks
- Template injection: User input in server-side template rendering

**CWEs:** CWE-79, CWE-89, CWE-73, CWE-78, CWE-77, CWE-917, CWE-502

## A04:2021 — Insecure Design
**What to look for:**
- No threat modeling evidence (no security design docs, no abuse cases)
- Business logic flaws (negative quantities, race conditions in payments)
- No rate limiting on resource-intensive operations
- Missing CAPTCHA on public forms
- No input validation schema (Joi, Zod, Pydantic, marshmallow absent)
- Trust boundaries not defined between components
- No separation of duties (same code handles user + admin actions)
- Missing defense in depth (single control point)

**CWEs:** CWE-256, CWE-501, CWE-522, CWE-269

## A05:2021 — Security Misconfiguration
**What to look for:**
- Debug mode enabled: `DEBUG = True`, `app.debug = True`, `NODE_ENV=development` in prod
- Default credentials: `admin/admin`, `root/root`, `test/test`
- Unnecessary features enabled (directory listing, admin panels exposed)
- Stack traces / error details returned to users
- Missing security headers: `X-Content-Type-Options`, `X-Frame-Options`, `CSP`, `HSTS`
- CORS `origin: '*'` or `CORS_ALLOW_ALL_ORIGINS = True`
- Cloud storage buckets/blobs publicly accessible
- Unnecessary open ports / services
- XML External Entities (XXE) enabled in XML parsers
- Default configurations unchanged

**CWEs:** CWE-16, CWE-611, CWE-489, CWE-209, CWE-942

## A06:2021 — Vulnerable and Outdated Components
**What to look for:**
- Known vulnerable dependencies (check `package.json`, `requirements.txt`, `pom.xml`, `Gemfile`)
- Outdated frameworks / libraries with known CVEs
- No dependency update process (no Dependabot, Renovate, or similar)
- Unsupported / end-of-life software versions
- No SBOM (Software Bill of Materials)
- Dependencies from untrusted sources
- Pinned versions that are years old

**CWEs:** CWE-1104, CWE-937

## A07:2021 — Identification and Authentication Failures
**What to look for:**
- No brute force protection (no rate limiting on login, no account lockout)
- Weak password policies (no minimum length, no complexity requirements)
- Credential stuffing vulnerability (no CAPTCHA, no MFA)
- JWT flaws: `algorithms: ['none']`, `verify=False`, short secrets, no expiration
- Session fixation: Session ID not regenerated after login
- Session cookies missing `HttpOnly`, `Secure`, `SameSite` attributes
- Password stored in plaintext or weak hash (MD5, SHA1 without salt)
- Default credentials in production
- Missing MFA on admin/sensitive operations

**CWEs:** CWE-287, CWE-384, CWE-256, CWE-307, CWE-613, CWE-347

## A08:2021 — Software and Data Integrity Failures
**What to look for:**
- Insecure deserialization: `pickle.loads()`, `yaml.load()` without SafeLoader, `unserialize()` in PHP
- No integrity checks on updates (missing checksums, signatures)
- CI/CD pipeline without integrity verification
- Auto-update without signature validation
- Dependencies from CDN without SRI (Subresource Integrity)
- Unsigned commits / releases
- No code review process

**CWEs:** CWE-502, CWE-829, CWE-494, CWE-915

## A09:2021 — Security Logging and Monitoring Failures
**What to look for:**
- No logging of security events (login, failed login, access denied, data changes)
- Sensitive data in logs: passwords, credit cards, tokens, PII
- Logs not centralized or easily searchable
- No alerting on suspicious events
- Log injection possible (user input written to logs without sanitization)
- Insufficient audit trail for compliance
- No log retention policy
- Logs stored unprotected

**CWEs:** CWE-778, CWE-117, CWE-223, CWE-532

## A10:2021 — Server-Side Request Forgery (SSRF)
**What to look for:**
- `requests.get(user_url)`, `fetch(req.body.url)`, `urllib.request.urlopen(param)`
- URL fetching without allowlist validation
- Internal network access via user-supplied URLs
- Cloud metadata endpoint access: `http://169.254.169.254/`
- PDF generators / image processors that fetch URLs
- Webhook URLs without validation
- DNS rebinding potential

**CWEs:** CWE-918
