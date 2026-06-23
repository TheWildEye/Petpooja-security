#!/bin/bash
# ==============================================================================
# Claude Code Petpooja Security - Installation Script (macOS / Linux)
# ==============================================================================
# Installs custom slash commands, agents, and skills into your project directory.
#
# Usage:
#   Project-level (current workspace):
#     ./install.sh
#
#   Global-level (any workspace you open with Claude Code):
#     ./install.sh --global
# ==============================================================================

set -e

# --- CONFIGURATION (Change this to match your repository URL) ---
GITHUB_USER="TheWildEye"
GITHUB_REPO="Petpooja-security"
BRANCH="main"
# ================================================================

# Parse command line arguments
GLOBAL_INSTALL=false
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --global) GLOBAL_INSTALL=true ;;
    --user) GITHUB_USER="$2"; shift ;;
    --repo) GITHUB_REPO="$2"; shift ;;
    --branch) BRANCH="$2"; shift ;;
    *) echo "Unknown parameter passed: $1"; exit 1 ;;
  esac
  shift
done

BASE_URL="https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$BRANCH/.claude"

TARGET_DIR="./.claude"
if [ "$GLOBAL_INSTALL" = true ]; then
  TARGET_DIR="$HOME/.claude"
fi

echo "==============================================="
echo " Installing Petpooja Security Agent"
echo " Target Directory: $TARGET_DIR"
echo " Source: $GITHUB_USER/$GITHUB_REPO @ $BRANCH"
echo "==============================================="

# Ensure directories exist
mkdir -p "$TARGET_DIR/commands"
mkdir -p "$TARGET_DIR/agents"
mkdir -p "$TARGET_DIR/skills"

# Download settings
echo "Fetching settings.json..."
curl -fsSL "$BASE_URL/settings.json" -o "$TARGET_DIR/settings.json"

# Download commands
echo "Fetching commands..."
for cmd in tiger-security-assess tiger-compliance-audit tiger-quick-scan tiger-fix-issue; do
  curl -fsSL "$BASE_URL/commands/$cmd.md" -o "$TARGET_DIR/commands/$cmd.md"
done

# Download agents
echo "Fetching agents..."
for agent in sast-engine secret-hunter dast-engine compliance-engine security-reviewer; do
  curl -fsSL "$BASE_URL/agents/$agent.md" -o "$TARGET_DIR/agents/$agent.md"
done

# Download skills
echo "Fetching skills..."
for skill in owasp-top10 mitre-cwe mobile-security legal; do
  curl -fsSL "$BASE_URL/skills/$skill.md" -o "$TARGET_DIR/skills/$skill.md"
done

echo "==============================================="
echo "✅ Installation Complete!"
echo "To run the scans, start 'claude' CLI in this directory and type:"
echo "  /tiger-security-assess   - Run full SAST + DAST + secrets + Indian compliance scan"
echo "  /tiger-compliance-audit  - Run deep Indian regulatory compliance audit"
echo "  /tiger-quick-scan        - Run rapid SAST & secret checks"
echo "  /tiger-fix-issue         - Interactively apply secure fixes to vulnerabilities"
echo "==============================================="
