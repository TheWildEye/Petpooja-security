# MITRE CWE — Top 25 Most Dangerous Software Weaknesses

## CWE Mapping Table

| CWE ID | Name | Description | OWASP | CVSS Range | Example |
|--------|------|-------------|-------|------------|---------|
| CWE-787 | Out-of-bounds Write | Writing past buffer boundary | A03 | 7.5-9.8 | Buffer overflow in C/C++ `strcpy()` |
| CWE-79 | Cross-site Scripting (XSS) | Injection of scripts via user input into web output | A03 | 4.3-6.1 | `innerHTML = req.query.name` |
| CWE-89 | SQL Injection | User input in SQL queries without parameterization | A03 | 7.5-9.8 | `f"SELECT * FROM users WHERE id={uid}"` |
| CWE-416 | Use After Free | Accessing memory after it has been freed | A03 | 7.5-9.8 | Dangling pointer dereference in C/C++ |
| CWE-78 | OS Command Injection | User input passed to shell commands | A03 | 7.5-9.8 | `os.system(f"ping {host}")` |
| CWE-20 | Improper Input Validation | Missing or insufficient input validation | A03 | 5.0-9.8 | No type/length/range check on parameters |
| CWE-125 | Out-of-bounds Read | Reading past buffer boundary | A03 | 5.0-7.5 | Heartbleed (CVE-2014-0160) |
| CWE-22 | Path Traversal | User-controlled filename accessing arbitrary files | A01 | 5.0-7.5 | `open(f"uploads/{user_filename}")` |
| CWE-352 | Cross-Site Request Forgery (CSRF) | Forging requests on behalf of authenticated user | A01 | 4.3-8.8 | State-changing POST without CSRF token |
| CWE-434 | Unrestricted Upload | Uploading dangerous file types | A04 | 7.5-9.8 | Upload `.php` file to web directory |
| CWE-862 | Missing Authorization | No access control check on sensitive operation | A01 | 5.0-9.8 | Admin endpoint without role check |
| CWE-476 | NULL Pointer Dereference | Dereferencing null pointer | A03 | 5.0-7.5 | Crash via unchecked null return |
| CWE-287 | Improper Authentication | Broken or missing authentication | A07 | 7.5-9.8 | Login bypass via `verify=False` |
| CWE-190 | Integer Overflow | Arithmetic overflow leading to unexpected behavior | A03 | 5.0-9.8 | Size calculation overflow in allocator |
| CWE-502 | Deserialization of Untrusted Data | Deserializing attacker-controlled data | A08 | 7.5-9.8 | `pickle.loads(user_data)` |
| CWE-77 | Command Injection | Injection into command string | A03 | 7.5-9.8 | `eval(user_input)` |
| CWE-119 | Buffer Overflow | Operations on buffer without bounds checking | A03 | 7.5-9.8 | Classic stack/heap overflow |
| CWE-798 | Hardcoded Credentials | Credentials embedded in source code | A07 | 7.5-9.8 | `password = "admin123"` |
| CWE-918 | Server-Side Request Forgery (SSRF) | Server makes requests to attacker-specified URL | A10 | 5.0-9.8 | `requests.get(user_url)` |
| CWE-306 | Missing Authentication for Critical Function | Critical operation without auth | A07 | 7.5-9.8 | Admin API without login check |
| CWE-362 | Race Condition (TOCTOU) | Time-of-check to time-of-use race | A04 | 5.0-8.1 | File access race in privilege check |
| CWE-269 | Improper Privilege Management | Excessive privileges or privilege escalation | A01 | 7.5-9.8 | User escalating to admin role |
| CWE-94 | Code Injection | User input executed as code | A03 | 7.5-9.8 | `eval(request.body.code)` |
| CWE-863 | Incorrect Authorization | Authorization check present but flawed | A01 | 5.0-9.8 | Role check that can be bypassed |
| CWE-276 | Incorrect Default Permissions | Overly permissive default file/resource permissions | A05 | 5.0-7.5 | World-readable config files |

## Additional Important CWEs

| CWE ID | Name | OWASP | Quick Detection |
|--------|------|-------|-----------------|
| CWE-311 | Missing Encryption of Sensitive Data | A02 | PII/financial data stored without encryption |
| CWE-312 | Cleartext Storage of Sensitive Info | A02 | Passwords in plaintext, card numbers unencrypted |
| CWE-319 | Cleartext Transmission | A02 | HTTP for sensitive data, no TLS |
| CWE-321 | Hardcoded Cryptographic Key | A02 | `encryption_key = "hardcoded"` |
| CWE-327 | Use of Broken Crypto Algorithm | A02 | MD5, SHA1 for passwords, DES, RC4 |
| CWE-330 | Insufficient Randomness | A02 | `Math.random()` for tokens |
| CWE-347 | Improper Verification of Crypto Signature | A07 | JWT `algorithms: ['none']` |
| CWE-384 | Session Fixation | A07 | No session regen after login |
| CWE-489 | Active Debug Code | A05 | `DEBUG = True` in production |
| CWE-532 | Insertion of Sensitive Info into Log | A09 | `log.info(f"password={pwd}")` |
| CWE-601 | Open Redirect | A01 | `redirect(user_url)` without validation |
| CWE-611 | Improper Restriction of XXE | A05 | XML parser with external entities enabled |
| CWE-639 | IDOR via User-Controlled Key | A01 | `/user/:id` without ownership check |
| CWE-942 | Overly Permissive CORS | A05 | `Access-Control-Allow-Origin: *` |

## CWE → Severity Mapping (Default)
- **CRITICAL (CVSS 9.0+):** CWE-89, CWE-78, CWE-502, CWE-798, CWE-287, CWE-94
- **HIGH (CVSS 7.0-8.9):** CWE-79, CWE-918, CWE-22, CWE-306, CWE-862, CWE-347
- **MEDIUM (CVSS 4.0-6.9):** CWE-352, CWE-327, CWE-330, CWE-489, CWE-942, CWE-601
- **LOW (CVSS <4.0):** CWE-532, CWE-276, CWE-223 (informational)
