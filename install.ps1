# ==============================================================================
# Claude Code Security Agent - Installation Script (Windows PowerShell)
# ==============================================================================
# Installs custom slash commands, agents, and skills into your project directory.
#
# Usage:
#   Project-level (current workspace):
#     .\install.ps1
#
#   Global-level (any workspace you open with Claude Code):
#     .\install.ps1 -Global
# ==============================================================================

param(
    [switch]$Global
)

$ErrorActionPreference = "Stop"

# --- CONFIGURATION (Change this to match your repository URL) ---
$GithubUser = "TheWildEye"
$GithubRepo = "Petpooja-security"
$Branch     = "main"
# ================================================================

$BaseUrl = "https://raw.githubusercontent.com/$GithubUser/$GithubRepo/$Branch/.claude"

$TargetDir = "./.claude"
if ($Global) {
    $TargetDir = "$Home/.claude"
}

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " Installing Claude Code Security & Compliance Agent" -ForegroundColor Cyan
Write-Host " Target Directory: $TargetDir" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

# Ensure directories exist
New-Item -ItemType Directory -Force -Path "$TargetDir/commands", "$TargetDir/agents", "$TargetDir/skills" | Out-Null

# Download settings
Write-Host "Fetching settings.json..."
Invoke-RestMethod -Uri "$BaseUrl/settings.json" -OutFile "$TargetDir/settings.json"

# Download commands
Write-Host "Fetching commands..."
@("security-assess", "compliance-audit", "quick-scan", "fix-issue") | ForEach-Object {
    Invoke-RestMethod -Uri "$BaseUrl/commands/$_.md" -OutFile "$TargetDir/commands/$_.md"
}

# Download agents
Write-Host "Fetching agents..."
@("sast-engine", "secret-hunter", "dast-engine", "compliance-engine", "security-reviewer") | ForEach-Object {
    Invoke-RestMethod -Uri "$BaseUrl/agents/$_.md" -OutFile "$TargetDir/agents/$_.md"
}

# Download skills
Write-Host "Fetching skills..."
@("owasp-top10", "mitre-cwe", "mobile-security", "legal") | ForEach-Object {
    Invoke-RestMethod -Uri "$BaseUrl/skills/$_.md" -OutFile "$TargetDir/skills/$_.md"
}

Write-Host "===============================================" -ForegroundColor Green
Write-Host "✅ Installation Complete!" -ForegroundColor Green
Write-Host "To run the scans, start 'claude' CLI in this directory and type:" -ForegroundColor Green
Write-Host "  /security-assess   - Run full SAST + DAST + secrets + Indian compliance scan" -ForegroundColor Green
Write-Host "  /compliance-audit  - Run deep Indian regulatory compliance audit" -ForegroundColor Green
Write-Host "  /quick-scan        - Run rapid SAST & secret checks" -ForegroundColor Green
Write-Host "  /fix-issue         - Interactively apply secure fixes to vulnerabilities" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
