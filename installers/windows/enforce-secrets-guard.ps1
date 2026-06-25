<#
  enforce-secrets-guard.ps1 - writes the Windows machine-wide managed-settings.json that
  MANDATORILY installs, enables and configures the secrets-guard plugin, and DISABLES
  Claude Code's "bypass permissions" mode.

  managed-settings.json is Claude Code's highest-precedence settings layer: users and
  projects cannot override it. On Windows it lives at:
      C:\ProgramData\ClaudeCode\managed-settings.json
  This file is a machine path under ProgramData, so writing it requires administrator
  rights and this script self-elevates (UAC). That admin requirement is ONLY about
  writing the managed-policy file - secrets-guard itself needs NO admin (see below).

  What it enforces:
    - permissions.disableBypassPermissionsMode = "disable"  (no --dangerously-skip / bypass)
    - the hsoft-claude-plugins marketplace (GitHub), locked down (strictKnownMarketplaces)
    - secrets-guard force-enabled (users cannot turn it off)
    - the full plugin policy: redaction-only by default (sandbox OFF), deny tool-input
      secrets, redact output, and the proactive full-vault redaction guard ON - so no
      vault value ever reaches the model's context

  How the guard runs (local model, as of v0.6.0): secrets-guard runs ENTIRELY PER-USER -
  no system service, no WinFsp driver, no administrator rights. The redaction guard reads
  the user's own vault through their local `ksm` / `op` profile (in its default location),
  loads every value into a per-session in-memory cache at session start, and redacts/blocks
  those values in prompts and tool I/O before they reach the model. After this script runs,
  the NEXT Claude Code start installs/activates the plugin automatically (its SessionStart
  hook puts the `secrets-guard` CLI on PATH, no admin). Each user just needs the Keeper
  `ksm` CLI installed and a profile initialized (`ksm profile init <token>`).

  Download + run on the target machine:
      powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://raw.githubusercontent.com/hsoftai/hsoft-claude-plugins/main/installers/windows/enforce-secrets-guard.ps1 -OutFile $env:TEMP\enforce-secrets-guard.ps1; & $env:TEMP\enforce-secrets-guard.ps1"

  Idempotent: re-running overwrites the file (the previous one is backed up first).
#>

[CmdletBinding()]
param(
  # Vault provider the plugin defaults to.
  [ValidateSet("auto", "keeper", "1password")]
  [string]$VaultProvider = "keeper",

  # Optional: the base64 Keeper Secrets Manager config (KSM_CONFIG). Leave empty to let each
  # user's local `ksm` profile back the guard instead of embedding the credential in the
  # (admin-readable) managed file.
  [string]$KsmConfig = "",

  # Where the audit log is written. Empty -> auditing left to the plugin default (off).
  [string]$AuditLogPath = "C:\ProgramData\secrets-guard\audit.log",

  # Sandbox / proactive redaction guard switches.
  # Sandbox defaults to OFF: the enforced behavior is redaction-only (no reference
  # rendering) - secrets-guard inspects every prompt and tool I/O and never lets a vault
  # value reach the model. SANDBOX=on enables in-place reference rendering. PreloadSecrets
  # keeps the proactive full-vault guard always on. GuardRequired controls fail-closed
  # behavior when the local vault is unavailable: auto degrades to the pattern detector,
  # on fails closed, off never fails closed.
  [ValidateSet("auto", "on", "off")][string]$Sandbox        = "off",
  [ValidateSet("auto", "on", "off")][string]$PreloadSecrets = "auto",
  [ValidateSet("auto", "on", "off")][string]$GuardRequired  = "auto",

  # Marketplace repo (override for a fork/mirror).
  [string]$Repo = "hsoftai/hsoft-claude-plugins",

  # Optional GitHub token for a PRIVATE marketplace repo (enables auto-update auth).
  [string]$GitHubToken = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Step($m) { Write-Host "[enforce] $m" }

# --- self-elevate (managed-settings lives under ProgramData; needs admin) ---
function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
  if (-not $PSCommandPath) {
    throw "Run this from a downloaded .ps1 file (needed for elevation), not piped into PowerShell."
  }
  Step "Administrator rights are required - requesting elevation (UAC)..."
  $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
  foreach ($kv in $PSBoundParameters.GetEnumerator()) {
    $argList += "-$($kv.Key)"
    $argList += "`"$($kv.Value)`""
  }
  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList
  exit
}

# --- build the managed settings document ---
$pluginEnv = [ordered]@{
  "CLAUDE_PLUGIN_OPTION_VAULT_PROVIDER"         = $VaultProvider
  "CLAUDE_PLUGIN_OPTION_BLOCK_ON_PROMPT_SECRET" = "true"
  "CLAUDE_PLUGIN_OPTION_TOOL_INPUT_POLICY"      = "deny"
  "CLAUDE_PLUGIN_OPTION_TOOL_OUTPUT_MODE"       = "redact"
  "CLAUDE_PLUGIN_OPTION_SANDBOX"                = $Sandbox
  "CLAUDE_PLUGIN_OPTION_PRELOAD_SECRETS"        = $PreloadSecrets
  "CLAUDE_PLUGIN_OPTION_GUARD_REQUIRED"         = $GuardRequired
}
if ($AuditLogPath) { $pluginEnv["CLAUDE_PLUGIN_OPTION_AUDIT_LOG_PATH"] = $AuditLogPath }
if ($KsmConfig)    { $pluginEnv["KSM_CONFIG"] = $KsmConfig }
if ($GitHubToken)  {
  $pluginEnv["GH_TOKEN"]     = $GitHubToken
  $pluginEnv["GITHUB_TOKEN"] = $GitHubToken
}

# Force an array (PowerShell would otherwise serialize a single element as an object).
[object[]]$strict = @([ordered]@{ "source" = "github"; "repo" = $Repo })

$settings = [ordered]@{
  "permissions" = [ordered]@{
    # Disable "bypass permissions" mode org-wide (cannot be re-enabled by the user).
    "disableBypassPermissionsMode" = "disable"
    "defaultMode"                  = "default"
  }
  "extraKnownMarketplaces" = [ordered]@{
    "hsoft-claude-plugins" = [ordered]@{
      "source"     = [ordered]@{ "source" = "github"; "repo" = $Repo }
      "autoUpdate" = $true
    }
  }
  "strictKnownMarketplaces" = $strict
  "enabledPlugins" = [ordered]@{
    "secrets-guard@hsoft-claude-plugins" = $true
  }
  "env" = $pluginEnv
}

$json = $settings | ConvertTo-Json -Depth 10

# --- write it (UTF-8 without BOM), backing up any existing file ---
$dir    = Join-Path $env:ProgramData "ClaudeCode"
$target = Join-Path $dir "managed-settings.json"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

if (Test-Path $target) {
  $bak = "$target.bak-" + (Get-Date -Format "yyyyMMdd-HHmmss")
  Copy-Item $target $bak -Force
  Step "Backed up existing file to $bak"
}

[System.IO.File]::WriteAllText($target, $json, (New-Object System.Text.UTF8Encoding($false)))
Step "Wrote $target"

# --- validate ---
try {
  $parsed = Get-Content $target -Raw | ConvertFrom-Json
  if ($parsed.permissions.disableBypassPermissionsMode -ne "disable") { throw "bypass-mode not disabled" }
  if (-not $parsed.enabledPlugins."secrets-guard@hsoft-claude-plugins") { throw "plugin not enabled" }
  Step "Validated: bypass-permissions disabled, secrets-guard force-enabled."
} catch {
  throw "Validation failed - the written file is not as expected: $_"
}

Write-Host ""
Step "Done. The policy is active for every Claude Code session on this machine."
Write-Host @"

Next steps (per user, NO admin):
  1. Install the Keeper 'ksm' CLI and initialize a profile:
       winget install KeeperSecurity.KeeperSecretsManager
       ksm profile init <ONE-TIME-TOKEN>
     (or pass -KsmConfig '<base64>' to embed the credential in the managed file).
  2. Open a NEW Claude Code session - the plugin installs and activates automatically
     (its SessionStart hook puts 'secrets-guard' on PATH and warms the in-memory cache).
     You can also run 'secrets-guard install' and verify with 'secrets-guard doctor'.

Settings written to: $target
"@
