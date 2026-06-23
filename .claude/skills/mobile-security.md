# Mobile Security — Android & iOS Checks

## Android Security Checks

### AndroidManifest.xml Analysis
| # | Check | What to Detect | Risk |
|---|-------|---------------|------|
| M1 | Debug enabled | `android:debuggable="true"` | HIGH — allows debugging in prod |
| M2 | Backup enabled | `android:allowBackup="true"` (default) | MEDIUM — data extractable via adb |
| M3 | Cleartext traffic | `android:usesCleartextTraffic="true"` | HIGH — HTTP traffic allowed |
| M4 | Exported components | `android:exported="true"` without permission | HIGH — accessible by other apps |
| M5 | Custom permissions | Missing `android:protectionLevel="signature"` | MEDIUM — weak permission model |
| M6 | Deep link hijacking | Intent filters without verification | MEDIUM — link interception |
| M7 | Task hijacking | `android:taskAffinity` misuse | MEDIUM — UI spoofing |

### Insecure Data Storage (Android)
| # | Check | Pattern | Risk |
|---|-------|---------|------|
| M8 | SharedPreferences secrets | `SharedPreferences` storing tokens/passwords/keys | HIGH |
| M9 | SQLite plaintext | Sensitive data in SQLite without encryption | HIGH |
| M10 | External storage | `getExternalStorage()` for sensitive data | HIGH — world-readable |
| M11 | Logging secrets | `Log.d()`, `Log.i()` with sensitive data | MEDIUM |
| M12 | Clipboard data | Sensitive data copied to clipboard | MEDIUM |

### Network Security (Android)
| # | Check | Pattern | Risk |
|---|-------|---------|------|
| M13 | Trust all certs | Custom `TrustManager` accepting all certificates | CRITICAL |
| M14 | No cert pinning | Missing certificate pinning for API calls | MEDIUM |
| M15 | WebView JavaScript | `setJavaScriptEnabled(true)` + `addJavascriptInterface()` | HIGH |
| M16 | WebView file access | `setAllowFileAccess(true)` + `setAllowFileAccessFromFileURLs(true)` | HIGH |

### Code Security (Android)
| # | Check | Pattern | Risk |
|---|-------|---------|------|
| M17 | Hardcoded URLs | API endpoints hardcoded in source | MEDIUM |
| M18 | Hardcoded IPs | Internal IPs in code | LOW |
| M19 | Native lib issues | `System.loadLibrary()` with unprotected native code | MEDIUM |
| M20 | No ProGuard/R8 | Missing code obfuscation config | LOW |

## iOS Security Checks

### Info.plist Analysis
| # | Check | Pattern | Risk |
|---|-------|---------|------|
| I1 | ATS disabled | `NSAllowsArbitraryLoads = true` | HIGH — HTTP traffic allowed |
| I2 | ATS exceptions | `NSExceptionDomains` with `NSExceptionAllowsInsecureHTTPLoads` | MEDIUM |
| I3 | Custom URL schemes | `CFBundleURLSchemes` without validation | MEDIUM |
| I4 | Query schemes | Excessive `LSApplicationQueriesSchemes` | LOW |
| I5 | Background modes | Unnecessary background capabilities | LOW |

### Insecure Data Storage (iOS)
| # | Check | Pattern | Risk |
|---|-------|---------|------|
| I6 | NSUserDefaults | Storing secrets in `UserDefaults` / `NSUserDefaults` | HIGH |
| I7 | Plist storage | Sensitive data in `.plist` files | HIGH |
| I8 | CoreData plaintext | Unencrypted CoreData for sensitive info | MEDIUM |
| I9 | Keychain misuse | Wrong `kSecAttrAccessible` level (e.g., `kSecAttrAccessibleAlways`) | MEDIUM |
| I10 | Pasteboard | `UIPasteboard.general` with sensitive data | MEDIUM |

### Network Security (iOS)
| # | Check | Pattern | Risk |
|---|-------|---------|------|
| I11 | No cert pinning | Missing `URLSessionDelegate` pinning or TrustKit | MEDIUM |
| I12 | Trust all certs | Custom `URLSession` trusting all server certificates | CRITICAL |

### Code Security (iOS)
| # | Check | Pattern | Risk |
|---|-------|---------|------|
| I13 | Hardcoded secrets | API keys/tokens in Swift/ObjC source files | HIGH |
| I14 | No jailbreak detect | Missing jailbreak detection for sensitive apps | MEDIUM |
| I15 | Snapshot exposure | No screenshot protection on sensitive screens | LOW |
| I16 | Logging | `NSLog()`, `print()` with sensitive data | MEDIUM |

## Firebase Security (Cross-Platform)
| # | Check | Pattern | Risk |
|---|-------|---------|------|
| F1 | Open read rules | `".read": true` or `".read": "true"` | CRITICAL — anyone can read |
| F2 | Open write rules | `".write": true` or `".write": "true"` | CRITICAL — anyone can write |
| F3 | No auth rules | Rules not checking `auth != null` | HIGH |
| F4 | Exposed API key | Firebase config with API key in public repo | MEDIUM (restricted by default) |
| F5 | No validation rules | Missing `.validate` rules on data structure | MEDIUM |
| F6 | Cloud Storage open | Storage rules allowing public read/write | CRITICAL |

## React Native / Flutter Checks
| # | Check | Pattern | Risk |
|---|-------|---------|------|
| RN1 | AsyncStorage secrets | Storing tokens in `AsyncStorage` (unencrypted) | HIGH |
| RN2 | Hardcoded keys | API keys in JS bundle (easily extractable) | HIGH |
| RN3 | Debug bridge | React Native debugging enabled in release | HIGH |
| RN4 | Hermes bytecode | Sensitive logic in JS (easily reversible) | LOW |
| FL1 | shared_preferences | Storing secrets in `SharedPreferences` plugin | HIGH |
| FL2 | Plaintext assets | API keys in `assets/` folder | HIGH |
| FL3 | No obfuscation | Missing `--obfuscate` flag in Flutter build | LOW |
