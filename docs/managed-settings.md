# Enforcing secrets-guard org-wide with managed-settings.json

`managed-settings.json` is the highest-precedence Claude Code settings layer: it
cannot be overridden by user or project settings. Deploy it via MDM (Intune,
Jamf, Kandji) to enforce secrets-guard across the organization.

Paths:

- macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
- Linux: `/etc/claude-code/managed-settings.json`
- Windows: `C:\ProgramData\ClaudeCode\managed-settings.json`

## Full enforcement example

```json
{
  "extraKnownMarketplaces": {
    "hsoft-claude-plugins": {
      "source": { "source": "github", "repo": "hsoftai/hsoft-claude-plugins" },
      "autoUpdate": true
    }
  },
  "enabledPlugins": {
    "secrets-guard@hsoft-claude-plugins": true
  },
  "strictKnownMarketplaces": [
    { "source": "github", "repo": "hsoftai/hsoft-claude-plugins" }
  ],
  "env": {
    "CLAUDE_PLUGIN_OPTION_VAULT_PROVIDER": "keeper",
    "CLAUDE_PLUGIN_OPTION_BLOCK_ON_PROMPT_SECRET": "true",
    "CLAUDE_PLUGIN_OPTION_TOOL_INPUT_POLICY": "deny",
    "CLAUDE_PLUGIN_OPTION_TOOL_OUTPUT_MODE": "redact",
    "CLAUDE_PLUGIN_OPTION_AUDIT_LOG_PATH": "/var/log/secrets-guard/audit.log",
    "KSM_CONFIG": "<base64-keeper-config>"
  }
}
```

What each key does:

- **`extraKnownMarketplaces`** — auto-registers the marketplace; users don't run
  `marketplace add`.
- **`enabledPlugins`** — force-enables the plugin; users **cannot** disable it.
- **`strictKnownMarketplaces`** — lockdown: only this marketplace can be added.
- **`env`** — sets the plugin's options (inherited by the hook subprocess) and the
  vault's headless credentials (`KSM_CONFIG` for Keeper).

## Authentication for a private/auto-updating marketplace

- **GitHub** has first-class auto-update: set `GITHUB_TOKEN` / `GH_TOKEN` in `env`.
- **Air-gapped / zero-runtime-auth (recommended for fleets):** pre-populate the
  plugin with `CLAUDE_CODE_PLUGIN_SEED_DIR` and ship it via Intune. No git auth at
  runtime; works on any network; updates are a controlled re-deploy.

## Vault credentials on the fleet

- **Keeper:** redeem a one-time token once, store the resulting base64 config, and
  push it as `KSM_CONFIG` via `env`. The `ksm` CLI must be on `PATH`.
- **1Password:** the `op` CLI must be installed and the device authorized.
- On an Entra/Intune-joined fleet, consider Azure Key Vault with the developer's
  existing identity to avoid distributing vault tokens (extensible provider).

## Rollout order (recommended)

1. **Audit only** for 1–2 weeks: `tool_input_policy=warn`, `tool_output_mode=block`,
   `audit_log_path` set. Collect real data, tune `custom_patterns_path` and
   `allowlist_path`.
2. **Enforce:** switch `tool_input_policy=deny` and `tool_output_mode=redact`.
3. Pair with the network DLP gateway for full inline output redaction and to
   cover Claude Desktop / web.
