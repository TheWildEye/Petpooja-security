"""
=============================================================================
COMPREHENSIVE SECRET HUNTER VALIDATION SUITE
=============================================================================
Covers all modern secret categories per industry threat intelligence:
  - Authentication & Authorization
  - Database Credentials
  - Cloud Provider Credentials
  - Third-Party API Keys (including AI providers)
  - Encryption & Cryptography
  - Infrastructure & DevOps
  - Storage & CDN
  - Messaging & Event Systems
  - Mobile Application Secrets
  - Sensitive Configuration Values

Each section has:
  [DETECT]  — values matching real formats the scanner MUST flag
  [SKIP]    — false positives the scanner MUST ignore

Patterns sourced from: TruffleHog v3, Gitleaks v8, detect-secrets
All values are INTENTIONALLY FAKE and non-functional.
=============================================================================
"""

# =============================================================================
# 1. AUTHENTICATION & AUTHORIZATION
# =============================================================================

# ── JWT Secrets ────────────────────────────────────────────────────────────
# Pattern : (?i)(jwt[_-]?secret|jwt_signing_key)\s*[:=]\s*["'][^"']{8,}["']
# [DETECT]
JWT_SECRET            = "hs256-super-secret-jwt-signing-key-never-expose"
JWT_SIGNING_KEY       = "RS256-jwt-private-signing-key-AbCdEfGhIjKlMnOp"
JWT_PRIVATE_KEY       = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5EXAMPLEFAKEKEY==
-----END RSA PRIVATE KEY-----"""

# [SKIP] — placeholder/template values
JWT_SECRET_PLACEHOLDER = "your-jwt-secret-here"
JWT_SECRET_ENV_REF     = "${JWT_SECRET}"

# ── Session Secrets ────────────────────────────────────────────────────────
# Pattern : (?i)(session[_-]?secret|express.*secret)\s*[:=]\s*["'][^"']{8,}
# [DETECT]
SESSION_SECRET        = "express-session-secret-AbCdEfGhIjKlMnOpQrSt"
COOKIE_SECRET         = "cookie-signing-secret-AbCdEfGhIjKlMnOpQrSt"

# [SKIP]
SESSION_SECRET_SKIP   = "replace-with-strong-random-session-secret"

# ── OAuth Client Secrets ───────────────────────────────────────────────────
# Pattern : (?i)(oauth|client)[_-]?secret\s*[:=]\s*["'][^"']{8,}
# [DETECT]
OAUTH_CLIENT_SECRET   = "oauth2-client-secret-AbCdEfGhIjKlMnOpQrStUv"
GOOGLE_CLIENT_SECRET  = "GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz"

# [SKIP]
OAUTH_SECRET_SKIP     = "${GOOGLE_CLIENT_SECRET}"

# ── SAML Certificates / Private Keys ──────────────────────────────────────
# Pattern : -----BEGIN (RSA|EC|OPENSSH|) PRIVATE KEY-----
# [DETECT]
SAML_PRIVATE_KEY      = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7EXAMPLEFAKE==
-----END PRIVATE KEY-----"""

# ── API Auth Tokens / Bearer Tokens ───────────────────────────────────────
# Pattern : (?i)(bearer|auth[_-]?token|api[_-]?token)\s*[:=]\s*["'][A-Za-z0-9._-]{20,}
# [DETECT]
API_AUTH_TOKEN        = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.FAKETOKEN.FAKESIG"
INTERNAL_API_TOKEN    = "iat-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMn"

# ── Refresh Token Secrets ──────────────────────────────────────────────────
# [DETECT]
REFRESH_TOKEN_SECRET  = "refresh-token-signing-secret-AbCdEfGhIjKlMnOp"

# =============================================================================
# 2. DATABASE CREDENTIALS
# =============================================================================

# ── Generic DB username/password ──────────────────────────────────────────
# Pattern : (?i)(db|database)[_-]?(pass(word)?|pwd)\s*[:=]\s*["'][^"']{4,}
# [DETECT]
DB_USERNAME           = "prod_admin_user"
DB_PASSWORD           = "Pr0d@dm!nP@ssw0rd2024"

# ── Connection Strings with credentials ───────────────────────────────────
# Pattern : (?i)(postgresql|mysql|mariadb|mssql|sqlite):\/\/[^:]+:[^@]+@
# [DETECT]
POSTGRESQL_URL        = "postgresql://prod_admin:Pr0d@dm!n@db.internal.company.com:5432/maindb"
MYSQL_URL             = "mysql://app_user:MySQLPass123!@mysql.internal:3306/appdb"
MARIADB_URL           = "mariadb://admin:MariaDBP@ss@mariadb.internal:3306/users"
MSSQL_URL             = "mssql://sa:MsSQLAdm!n@sqlserver.internal:1433/MainDB"

# ── MongoDB URI ────────────────────────────────────────────────────────────
# Pattern : mongodb(\+srv)?:\/\/[^:]+:[^@]+@
# [DETECT]
MONGODB_URI           = "mongodb+srv://root:MongoP@ssw0rd2024@cluster0.abcdef.mongodb.net/prod"

# ── Redis with auth ────────────────────────────────────────────────────────
# Pattern : redis:\/\/:[^@]+@
# [DETECT]
REDIS_URL             = "redis://:RedisAuthP@ss2024@redis.internal:6379/0"

# [SKIP] — localhost with no real password
REDIS_LOCAL_SKIP      = "redis://localhost:6379"
DB_URL_PLACEHOLDER    = "postgresql://user:password@localhost:5432/mydb"

# =============================================================================
# 3. CLOUD PROVIDER CREDENTIALS
# =============================================================================

# ── AWS ────────────────────────────────────────────────────────────────────
# Access Key: AKIA[0-9A-Z]{16}
# [DETECT]
AWS_ACCESS_KEY_ID        = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# Session tokens are long and start with //
AWS_SESSION_TOKEN        = "FQoGZXIvYXdzEJr//AbCdEfGhIjKlMnOpQrStUvWxYz//AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKl"

# [SKIP] — IAM role reference, no static key
AWS_ROLE_ARN_SKIP        = "arn:aws:iam::123456789012:role/MyServiceRole"

# ── Azure ──────────────────────────────────────────────────────────────────
# Storage Key: base64, 88 chars ending in ==
# [DETECT]
AZURE_STORAGE_KEY        = "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv=="
AZURE_CLIENT_SECRET      = "AbCdEfGhIjKlMnOpQrStUvWxYz~AbCdEfGhIjKl"
AZURE_SAS_TOKEN          = "sv=2021-06-08&ss=b&srt=sco&sp=rwdlacupitfx&se=2025-01-01&st=2024-01-01&spr=https&sig=AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp"

# ── GCP Service Account Key (JSON) ────────────────────────────────────────
# Pattern : "type"\s*:\s*"service_account"
# [DETECT]
GCP_SERVICE_ACCOUNT_JSON = """{
  "type": "service_account",
  "project_id": "my-prod-project",
  "private_key_id": "abcdef1234567890abcdef1234567890abcdef12",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEFAKEKEY==\\n-----END RSA PRIVATE KEY-----\\n",
  "client_email": "svc-account@my-prod-project.iam.gserviceaccount.com"
}"""

# ── Firebase Admin SDK ────────────────────────────────────────────────────
# Pattern : "type"\s*:\s*"service_account" with firebase domain in client_email
# [DETECT]
FIREBASE_ADMIN_KEY      = "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz01234"   # Firebase Browser Key
FIREBASE_SERVICE_JSON   = '{"type":"service_account","private_key":"-----BEGIN RSA PRIVATE KEY-----\\nFAKE\\n-----END RSA PRIVATE KEY-----\\n"}'

# =============================================================================
# 4. THIRD-PARTY API KEYS
# =============================================================================

# ── OpenAI (all current key formats) ──────────────────────────────────────
# [DETECT]
OPENAI_LEGACY_KEY     = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrSt"
OPENAI_PROJECT_KEY    = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz_AbCdEfGhIjKlMnOpQrStUvWx"
OPENAI_SVCACCT_KEY    = "sk-svcacct-AbCdEfGhIjKlMnOpQrStUvWxYz_AbCdEfGhIjKlMnOpQr"
OPENAI_ADMIN_KEY      = "sk-admin-AbCdEfGhIjKlMnOpQrStUvWxYz_AbCdEfGhIjKlMnOpQrSt"

# [SKIP]
OPENAI_TEST_SKIP      = "sk-test-AbCdEfGhIjKlMnOpQrStUvWxYz"
OPENAI_NONE_SKIP      = "sk-None-AbCdEfGhIjKlMnOpQrStUvWxYz"
OPENAI_ENV_SKIP       = "${OPENAI_API_KEY}"

# ── Anthropic (Claude) ─────────────────────────────────────────────────────
# Pattern : sk-ant-api03-[0-9A-Za-z_-]{93}AA  (108 chars total, ends in AA)
# [DETECT]
ANTHROPIC_API_KEY     = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEAA"

# [SKIP]
ANTHROPIC_SKIP        = "sk-ant-api03-EXAMPLE-REPLACE-THIS-AbCdEfGhIjKlAA"

# ── Google Gemini / AI Studio ──────────────────────────────────────────────
# Legacy: AIza[0-9A-Za-z-_]{35}   |  New 2025: AQ\.[a-zA-Z0-9_-]{30,}
# [DETECT]
GEMINI_LEGACY_KEY     = "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz01234"
GEMINI_NEW_KEY        = "AQ.AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIj"

# [SKIP]
GEMINI_PLACEHOLDER    = "AIzaSy-YOUR-GEMINI-API-KEY-HERE"
GEMINI_ENV_SKIP       = "${GEMINI_API_KEY}"

# ── Stripe ────────────────────────────────────────────────────────────────
# [DETECT]
# Real format: sk_live_[a-zA-Z0-9]{24,} — value below has _FAKE_ break to avoid GitHub push protection
STRIPE_SECRET_KEY     = "sk_live_FAKE_51AbCdEfGhIjKlMnOpQrStUv12"
STRIPE_RESTRICTED_KEY = "rk_live_FAKE_AbCdEfGhIjKlMnOpQrStUvWxYz"

# [SKIP] — test key, not live billing
STRIPE_TEST_KEY_SKIP  = "sk_test_51AbCdEfGhIjKlMnOpQrStUv12"

# ── Razorpay ──────────────────────────────────────────────────────────────
# [DETECT]
RAZORPAY_KEY_SECRET   = "rzp_live_AbCdEfGhIjKlMn"

# [SKIP]
RAZORPAY_TEST_SKIP    = "rzp_test_AbCdEfGhIjKlMn"

# ── PayPal ────────────────────────────────────────────────────────────────
# Pattern : A21AA[a-zA-Z0-9-_]{60,}  (Live client secret)
# [DETECT]
PAYPAL_CLIENT_SECRET  = "EAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCd"

# ── Twilio ────────────────────────────────────────────────────────────────
# Auth Token: [0-9a-f]{32} paired with Account SID AC[0-9a-f]{32}
# [DETECT]
# Real SID format: AC[0-9a-f]{32} — value below prefixed with FAKE to avoid GitHub push protection
TWILIO_ACCOUNT_SID    = "ACFAKE_abcdef1234567890abcdef123456"
TWILIO_AUTH_TOKEN     = "FAKE_abcdef1234567890abcdef12345678"

# ── SendGrid ─────────────────────────────────────────────────────────────
# Pattern : SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}
# [DETECT]
SENDGRID_API_KEY      = "SG.AbCdEfGhIjKlMnOpQrStUvWx.AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMn"

# ── Mailgun ───────────────────────────────────────────────────────────────
# Pattern : key-[a-f0-9]{32}
# [DETECT]
# Real format: key-[a-f0-9]{32} — value below has FAKE infix
MAILGUN_API_KEY       = "key-FAKE1234abcdef1234567890abcdef12"

# ── Slack ─────────────────────────────────────────────────────────────────
# [DETECT]
# Real format: xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+ — FAKE infix to avoid push protection
SLACK_BOT_TOKEN       = "xoxb-FAKE-123456789012-AbCdEfGhIjKlMnOpQrStUvWx"
SLACK_USER_TOKEN      = "xoxp-FAKE-123456789012-AbCdEfGhIjKlMnOpQrStUvWx"
SLACK_APP_TOKEN       = "xapp-1-FAKE-AbCdEfGhIjKlMnOpQrStUvWx"
SLACK_SIGNING_SECRET  = "FAKE_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf"
SLACK_WEBHOOK_URL     = "https://hooks.slack.com/services/TFAKE567/BFAKE567/AbCdEfGhIjKlMnOpQrStUvWx"

# ── Discord ───────────────────────────────────────────────────────────────
# Bot token: MTIzNDU2Nzg5MDEyMzQ1Njc4.[A-Za-z0-9-_]{6}.[A-Za-z0-9-_]{27}
# [DETECT]
DISCORD_BOT_TOKEN     = "MTIzNDU2Nzg5MDEyMzQ1Njc4.AbCdEf.AbCdEfGhIjKlMnOpQrStUvWxYz"
DISCORD_CLIENT_SECRET = "AbCdEfGhIjKlMnOpQrStUvWx"

# ── GitHub ────────────────────────────────────────────────────────────────
# [DETECT]
GITHUB_PAT            = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AB"
GITHUB_OAUTH_TOKEN    = "gho_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AB"

# ── Hugging Face ──────────────────────────────────────────────────────────
# Pattern : hf_[a-zA-Z0-9]{34,}
# [DETECT]
# Real format: hf_[a-zA-Z0-9]{34,} — value below has FAKE infix
HUGGINGFACE_TOKEN     = "hf_FAKE_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf"

# [SKIP] — read-only public token
HUGGINGFACE_READ_SKIP = "hf_read_AbCdEfGhIjKlMnOpQrStUvWxYz"

# ── Perplexity AI ─────────────────────────────────────────────────────────
# Pattern : pplx-[a-zA-Z0-9]{48}
PERPLEXITY_API_KEY    = "pplx-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrSt"

# =============================================================================
# 5. ENCRYPTION & CRYPTOGRAPHY
# =============================================================================

# ── RSA / EC / OpenSSH Private Keys ───────────────────────────────────────
# Pattern : -----BEGIN (RSA|EC|OPENSSH|) PRIVATE KEY-----
# [DETECT]
RSA_PRIVATE_KEY       = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5FAKEEXAMPLEKEY==
-----END RSA PRIVATE KEY-----"""

EC_PRIVATE_KEY        = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIAbCdEfGhIjKlMnOpQrStUvWxYzFAKEEXAMPLE==
-----END EC PRIVATE KEY-----"""

OPENSSH_PRIVATE_KEY   = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA...FAKEEXAMPLE==
-----END OPENSSH PRIVATE KEY-----"""

PKCS8_PRIVATE_KEY     = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjFAKEEXAMPLE==
-----END PRIVATE KEY-----"""

# ── AES / HMAC / Symmetric Keys ───────────────────────────────────────────
# Pattern : (?i)(aes[_-]?key|hmac[_-]?secret|encryption[_-]?key)\s*[:=]\s*["'][^"']{16,}
# [DETECT]
AES_256_KEY           = "aes256-encryption-key-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf"
HMAC_SECRET           = "hmac-sha256-signing-key-AbCdEfGhIjKlMnOpQrSt"
ENCRYPTION_KEY        = "data-encryption-key-AbCdEfGhIjKlMnOpQrStUvWxYz"

# Key Encryption Keys / Data Encryption Keys
KEK                   = "key-encryption-key-AbCdEfGhIjKlMnOpQrStUvWxYz"
DEK                   = "data-encryption-key-AbCdEfGhIjKlMnOpQrStUvWx"

# [SKIP]
AES_KEY_SKIP          = "${AES_ENCRYPTION_KEY}"
HMAC_SECRET_SKIP      = "replace-with-strong-hmac-secret"

# =============================================================================
# 6. INFRASTRUCTURE & DEVOPS
# =============================================================================

# ── SSH Private Keys ──────────────────────────────────────────────────────
# (already covered in Section 5 — OPENSSH_PRIVATE_KEY)

# ── Kubernetes Service Account Token ──────────────────────────────────────
# Pattern : eyJhbGciOiJSUzI1NiIsImtpZCI6  (base64 JWT with k8s header)
# [DETECT]
K8S_SERVICE_ACCOUNT_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkFiQ2RFZkdoSWpLbE1uT3BRclN0VXZXeFl6In0.FAKETOKEN.FAKESIG"
K8S_SECRET_VALUE      = "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrSt"

# ── Docker Registry Credentials ───────────────────────────────────────────
# Pattern : (?i)(docker.*password|registry.*password)\s*[:=]\s*["'][^"']{4,}
# [DETECT]
DOCKER_REGISTRY_USER  = "registry-service-user"
DOCKER_REGISTRY_PASS  = "docker-registry-password-AbCdEfGhIjKlMnOpQrSt"

# ── Terraform Cloud Token ──────────────────────────────────────────────────
# Pattern : [a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,}
# [DETECT]
TERRAFORM_TOKEN       = "AbCdEfGhIjKlMn.atlasv1.AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp"

# ── Ansible Vault Password ────────────────────────────────────────────────
# Pattern : (?i)(ansible[_-]?vault[_-]?pass(word)?)\s*[:=]\s*["'][^"']{4,}
# [DETECT]
ANSIBLE_VAULT_PASS    = "ansible-vault-password-AbCdEfGhIjKlMnOpQrSt"

# ── CI/CD Tokens ──────────────────────────────────────────────────────────
# [DETECT]
GITHUB_ACTIONS_SECRET = "ghs_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
GITLAB_CI_TOKEN       = "glpat-AbCdEfGhIjKlMnOpQrStUv"
JENKINS_API_TOKEN     = "jenkins-api-AbCdEfGhIjKlMnOpQrStUvWxYz"
CIRCLECI_TOKEN        = "circle-token-AbCdEfGhIjKlMnOpQrStUvWxYzAbCd"

# =============================================================================
# 7. STORAGE & CDN
# =============================================================================

# ── S3 / MinIO / Backblaze ────────────────────────────────────────────────
# S3 uses same AWS key pattern — AKIAIOSFODNN7EXAMPLE
# MinIO: detected by var name + entropy
# Backblaze B2: K001[a-zA-Z0-9+/=]{31}
# [DETECT]
MINIO_ACCESS_KEY      = "minio-access-key-AbCdEfGhIjKlMnOpQrSt"
MINIO_SECRET_KEY      = "minio-secret-key-AbCdEfGhIjKlMnOpQrStUvWxYzAbCd"
BACKBLAZE_KEY_ID      = "b2-key-id-AbCdEfGhIjKlMnOpQrSt"
BACKBLAZE_APP_KEY     = "K001AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIj"

# ── CloudFront Signed URL Key ─────────────────────────────────────────────
# Pattern : -----BEGIN RSA PRIVATE KEY----- (used for CF signed URLs)
CLOUDFRONT_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2FAKEEXAMPLEKEYFORCLOUDFRONT==
-----END RSA PRIVATE KEY-----"""

# =============================================================================
# 8. MESSAGING & EVENT SYSTEMS
# =============================================================================

# ── MQTT ──────────────────────────────────────────────────────────────────
# Pattern : (?i)(mqtt[_-]?pass(word)?|mqtt[_-]?user)\s*[:=]\s*["'][^"']{4,}
# [DETECT]
MQTT_USERNAME         = "mqtt-broker-user"
MQTT_PASSWORD         = "mqtt-broker-password-AbCdEfGhIjKlMnOpQrSt"

# ── Kafka SASL ────────────────────────────────────────────────────────────
# Pattern : (?i)(kafka.*sasl.*password|sasl.*password)\s*[:=]\s*["'][^"']{4,}
# [DETECT]
KAFKA_SASL_USERNAME   = "kafka-sasl-user"
KAFKA_SASL_PASSWORD   = "kafka-sasl-password-AbCdEfGhIjKlMnOpQrSt"

# ── RabbitMQ ──────────────────────────────────────────────────────────────
# Pattern : amqp(s)?:\/\/[^:]+:[^@]+@
# [DETECT]
RABBITMQ_URL          = "amqp://admin:RabbitMQP@ss2024@rabbitmq.internal:5672/vhost"

# [SKIP]
RABBITMQ_LOCAL_SKIP   = "amqp://guest:guest@localhost:5672/"

# ── Elasticsearch ─────────────────────────────────────────────────────────
# Pattern : (?i)(elasticsearch.*pass(word)?|elastic.*password)\s*[:=]\s*["'][^"']{4,}
# [DETECT]
ELASTICSEARCH_USER    = "elastic"
ELASTICSEARCH_PASS    = "elastic-password-AbCdEfGhIjKlMnOpQrSt"
ELASTIC_CLOUD_ID      = "my-cluster:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlvOjQ0MyRAbCdEfGhIjKlMnOpQrStUvWxYz"
ELASTIC_API_KEY       = "AbCdEfGhIjKlMnOpQrSt:AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh"

# =============================================================================
# 9. MOBILE APPLICATION SECRETS
# =============================================================================

# ── Backend API Secrets (mobile apps often hardcode these) ───────────────
# Pattern : (?i)(api[_-]?secret|backend[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9._-]{16,}
# [DETECT]
MOBILE_BACKEND_SECRET = "mobile-backend-api-secret-AbCdEfGhIjKlMnOpQrSt"

# ── Firebase Cloud Messaging (FCM) Server Key ─────────────────────────────
# Pattern : AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}
# [DETECT]
FCM_SERVER_KEY        = "AAAA-AbCdE:APA91bAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKl"

# ── Firebase service account ──────────────────────────────────────────────
FIREBASE_ADMIN_SDK    = '{"type":"service_account","private_key":"-----BEGIN RSA PRIVATE KEY-----\\nFAKE\\n-----END RSA PRIVATE KEY-----\\n","client_email":"svc@project.iam.gserviceaccount.com"}'

# ── Android Keystore Password ─────────────────────────────────────────────
# Pattern : (?i)(keystore[_-]?pass(word)?|storepass)\s*[:=]\s*["'][^"']{4,}
# [DETECT]
KEYSTORE_PASSWORD     = "android-keystore-P@ssw0rd-AbCdEfGhIjKl"
KEY_ALIAS_PASSWORD    = "android-key-alias-P@ssw0rd"

# ── Apple APNs Authentication Key ─────────────────────────────────────────
# Pattern : -----BEGIN PRIVATE KEY----- (EC key for Apple push)
# [DETECT]
APPLE_APNS_KEY        = """-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgFAKEEXAMPLEAPPLE==
-----END PRIVATE KEY-----"""
APPLE_APNS_KEY_ID     = "AbCdEfGhIj"   # 10-char key ID paired with above
APPLE_TEAM_ID         = "AbCdEfGhIj"   # 10-char team ID

# =============================================================================
# 10. SENSITIVE CONFIGURATION VALUES
# =============================================================================

# ── Internal IPs / Hostnames (flag as LOW — informational) ────────────────
# Pattern : (10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)
# [DETECT — LOW severity, informational only]
INTERNAL_DB_HOST      = "10.0.1.100"
INTERNAL_SERVICE_URL  = "http://172.16.0.50:8080/api"
PRIVATE_REDIS_HOST    = "192.168.1.200"

# ── Production URLs hardcoded in source ───────────────────────────────────
# [DETECT — LOW severity]
PROD_API_URL          = "https://internal-api.company.petpooja.com"
STAGING_DB_HOST       = "staging-db.internal.petpooja.com"

# ── Default Credentials (highest risk) ────────────────────────────────────
# Pattern : (?i)(password|passwd)\s*[:=]\s*["'](admin|root|password|123456|changeme|default)
# [DETECT — CRITICAL]
DEFAULT_ADMIN_PASS    = "admin"
DEFAULT_ROOT_PASS     = "root"
DEFAULT_WEAK_PASS     = "password123"

# ── Backup Server Credentials ─────────────────────────────────────────────
# [DETECT]
BACKUP_SERVER         = "backup.internal.petpooja.com"
BACKUP_SERVER_USER    = "backup_admin"
BACKUP_SERVER_PASS    = "backup-server-P@ss2024-AbCdEfGhIjKl"

# ── Admin Emails (LOW risk — flag as informational) ───────────────────────
ADMIN_EMAIL           = "admin@petpooja.com"
SYSTEM_EMAIL          = "system-alerts@petpooja.com"

# =============================================================================
# FALSE POSITIVES — Global (SKIP across all sections)
# =============================================================================

# Variable references — always skip
ALL_ENV_REFS = {
    "DB_PASS":         "${DB_PASSWORD}",
    "JWT_KEY":         "os.environ['JWT_SECRET']",
    "AWS_KEY":         "process.env.AWS_ACCESS_KEY_ID",
    "OPENAI_KEY":      "${OPENAI_API_KEY}",
    "REDIS_URL_REF":   "%(REDIS_URL)s",
}

# Values with explicit placeholder markers — skip
ALL_PLACEHOLDERS = {
    "db_url":          "postgresql://user:password@localhost:5432/mydb",
    "api_key":         "replace-with-your-api-key",
    "secret":          "your-strong-secret-here",
    "token":           "REPLACE_ME_WITH_ACTUAL_TOKEN",
    "hmac":            "changeme-hmac-secret",
    "jwt_secret":      "your-jwt-secret-here",
    "keystore_pass":   "your-keystore-password",
}

# Masked / redacted values — skip
MASKED_VALUES = {
    "stripe":          "sk_live_****************************",
    "openai":          "sk-proj-************************************",
    "anthropic":       "sk-ant-api03-*****AA",
    "github":          "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "aws":             "AKIA****************",
}

# Localhost / loopback references — skip or flag LOW only
LOCAL_REFS = {
    "redis":           "redis://localhost:6379",
    "db":              "postgresql://localhost:5432/mydev",
    "mqtt":            "mqtt://localhost:1883",
    "rabbitmq":        "amqp://guest:guest@localhost:5672/",
}
