"""
=============================================================================
TEST CASE: Shared & Default Credentials — CERT-IN Violation (Prohibited)
=============================================================================
CERT-IN Guidelines explicitly PROHIBIT shared/generic accounts.
This file tests compliance-engine detection of:
  1. Shared credentials (one password used by multiple people/services)
  2. Default credentials (unchanged from install defaults)
  3. False positives (individual service accounts — should NOT be flagged)
=============================================================================
"""

# ---------------------------------------------------------------------------
# SECTION 1 — SHOULD DETECT: Shared credentials (CERT-IN violation)
# CERT-IN mandates individual, non-shared accounts for all access.
# ---------------------------------------------------------------------------

# ── Shared team database credentials ──────────────────────────────────────
# Violation: One password used by the entire dev team → CERT-IN prohibited
TEAM_DB_USER     = "shared_admin"
TEAM_DB_PASSWORD = "TeamPassword2024!"

# ── Generic service account (shared across services) ──────────────────────
# Violation: Generic name implies shared use → not attributable to one actor
SERVICE_ACCOUNT_USER     = "service_user"
SERVICE_ACCOUNT_PASSWORD = "ServiceP@ss123"

# ── Shared API key distributed to all developers ──────────────────────────
# Violation: No audit trail — any dev can use this key without accountability
SHARED_API_KEY    = "shared-key-for-all-devs-abc123def456"
TEAM_ACCESS_TOKEN = "team-token-everyone-uses-this"

# ── Shared cloud credentials ───────────────────────────────────────────────
# Pattern : AKIA[0-9A-Z]{16}  (AWS key format — shared here)
# Violation: Shared AWS keys cannot be individually revoked or audited
AWS_SHARED_ACCESS_KEY = "AKIASHAREDTEAM0000001"
AWS_SHARED_SECRET_KEY = "SharedSecretForAllTeamMembers/Example+Key"

# ── Shared admin panel access ──────────────────────────────────────────────
ADMIN_USER     = "admin"
ADMIN_PASSWORD = "admin123"   # also a default credential violation

# ── Shared monitoring dashboard ───────────────────────────────────────────
GRAFANA_USER     = "team_monitor"
GRAFANA_PASSWORD = "MonitorPass2024"


# ---------------------------------------------------------------------------
# SECTION 2 — SHOULD DETECT: Default / unchanged credentials
# PCI DSS Req 2 + CERT-IN require all default credentials be changed.
# ---------------------------------------------------------------------------

# ── Blank / empty passwords ────────────────────────────────────────────────
REDIS_PASSWORD = ""             # default: no password set (CWE-258)

# ── Vendor default passwords still in use ─────────────────────────────────
MYSQL_ROOT_PASSWORD        = "root"       # MySQL default
POSTGRES_PASSWORD          = "postgres"   # PostgreSQL default
MONGO_INITDB_ROOT_PASSWORD = "changeme"   # MongoDB default placeholder


# ---------------------------------------------------------------------------
# SECTION 3 — FALSE POSITIVES (should NOT be flagged)
# These demonstrate correct individual, non-shared credential patterns.
# The scanner must recognize these as compliant and skip them.
# ---------------------------------------------------------------------------

# ── Per-developer individual credentials — compliant ──────────────────────
# Each developer has their own unique, non-shared credential
DEV_VYOM_API_KEY   = "${VYOM_API_KEY}"       # injected from env at runtime
DEV_SAHIL_API_KEY  = "${SAHIL_API_KEY}"      # injected from env at runtime

# ── IAM role-based access (no shared key) — compliant ─────────────────────
# IAM roles don't produce static credentials — nothing to flag
AWS_ROLE_ARN = "arn:aws:iam::123456789012:role/MyServiceRole"

# ── Service principal with rotation — compliant ────────────────────────────
# Credential rotated weekly via vault — short-lived, individual, auditable
VAULT_AGENT_TOKEN = "${VAULT_TOKEN}"         # injected by HashiCorp Vault agent

# ── Example placeholder in documentation — compliant ──────────────────────
EXAMPLE_PASSWORD = "your-strong-unique-password-here"
EXAMPLE_API_KEY  = "replace-with-your-individual-api-key"
