#!/bin/bash
# ==============================================================================
# Claude Code Security Agent - Installation Script (macOS / Linux)
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

BASE_URL="https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$BRANCH/.claude"

TARGET_DIR="./.claude"
if [ "$1" == "--global" ]; then
  TARGET_DIR="$HOME/.claude"
fi

echo "==============================================="
echo " Installing Claude Code Security & Compliance Agent"
echo " Target Directory: $TARGET_DIR"
echo "==============================================="

# Ensure directories exist
mkdir -p "$TARGET_DIR/commands"
mkdir -p "$TARGET_DIR/agents"
mkdir -p "$TARGET_DIR/skills"

# Download settings
echo "Fetching settings.json..."
curl -sSL "$BASE_URL/settings.json" -o "$TARGET_DIR/settings.json"

# Download commands
echo "Fetching commands..."
for cmd in security-assess compliance-audit quick-scan fix-issue; do
  curl -sSL "$BASE_URL/commands/$cmd.md" -o "$TARGET_DIR/commands/$cmd.md"
done

# Download agents
echo "Fetching agents..."
for agent in sast-engine secret-hunter dast-engine compliance-engine security-reviewer; do
  curl -sSL "$BASE_URL/agents/$agent.md" -o "$TARGET_DIR/agents/$agent.md"
done

# Download skills
echo "Fetching skills..."
for skill in owasp-top10 mitre-cwe mobile-security legal; do
  curl -sSL "$BASE_URL/skills/$skill.md" -o "$TARGET_DIR/skills/$skill.md"
done

echo "==============================================="
echo "✅ Installation Complete!"
echo "To run the scans, start 'claude' CLI in this directory and type:"
echo "  /security-assess   - Run full SAST + DAST + secrets + Indian compliance scan"
echo "  /compliance-audit  - Run deep Indian regulatory compliance audit"
echo "  /quick-scan        - Run rapid SAST & secret checks"
echo "  /fix-issue         - Interactively apply secure fixes to vulnerabilities"
echo "==============================================="
