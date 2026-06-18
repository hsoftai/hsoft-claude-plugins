# Enforcing secrets-guard org-wide with managed-settings.json

`managed-settings.json` is the highest-precedence Claude Code settings layer: it
cannot be overridden by user or project settings. Deploy it via MDM (Intune,
Jamf, Kandji) to enforce secrets-guard across the organization.

Paths:

- macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
- Linux: `/etc/claude-code/managed-settings.json`
- Windows: `C:\ProgramData\ClaudeCode\managed-settings.json`

## Windows one-shot enforcement script

On Windows you can write the managed file (and disable "bypass permissions" mode) in one
step with `installers/windows/enforce-secrets-guard.ps1`. It self-elevates and writes
`C:\ProgramData\ClaudeCode\managed-settings.json`. Download and run it on the target machine:

```powershell
powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://raw.githubusercontent.com/hsoftai/hsoft-claude-plugins/main/installers/windows/enforce-secrets-guard.ps1 -OutFile $env:TEMP\enforce-secrets-guard.ps1; & $env:TEMP\enforce-secrets-guard.ps1"
```

Pass `-KsmConfig '<base64>'` to embed the Keeper credential, or leave it out to let the
`sandbox-dlp` service ingest the local `ksm` profile. For per-process file rendering also
run `installers/windows/sandbox-dlp-setup.ps1` (installs WinFsp + the service).

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
    "CLAUDE_PLUGIN_OPTION_SANDBOX": "auto",
    "CLAUDE_PLUGIN_OPTION_KERNEL_DLP": "auto",
    "CLAUDE_PLUGIN_OPTION_PRELOAD_SECRETS": "auto",
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

### Execution & redaction options

- **`SANDBOX`** (`auto` | `on` | `off`) — the sandbox renders vault references (in the
  environment and in files under the working directory) into real values for the
  command's process only. `off` is the **kill switch**: no command is wrapped and no
  file is rendered (references are left literal). `auto` enables it wherever a vault can
  resolve; `on` forces it.
- **`KERNEL_DLP`** (`auto` | `require` | `off`, **Windows only**) — selects the WinFsp
  `sandbox-dlp` service for per-process file rendering. `off` keeps the in-place
  renderer; `require` fails closed when the service is absent (never writes a value to
  disk); `auto` uses the service when present. Set `off` to disable the kernel-DLP path
  on Windows independently of `SANDBOX`.
- **`PRELOAD_SECRETS`** (`auto` | `on` | `off`) — the proactive full-vault redaction
  guard. When enabled (default), every value the vault exposes is held in memory (in the
  per-session cache on macOS/Linux, in the `sandbox-dlp` service on Windows) and any
  prompt, tool input, tool output, or file read containing one of those values — in any
  encoding — is redacted or blocked before it reaches the model, even if the value was
  never referenced. Values never touch disk and never reach the model. `off` limits the
  guard to values resolved during the session.

## Authentication for a private/auto-updating marketplace

- **GitHub** has first-class auto-update: set `GITHUB_TOKEN` / `GH_TOKEN` in `env`.
- **Air-gapped / zero-runtime-auth (recommended for fleets):** pre-populate the
  plugin with `CLAUDE_CODE_PLUGIN_SEED_DIR` and ship it via Intune. No git auth at
  runtime; works on any network; updates are a controlled re-deploy.

## Vault credentials on the fleet

The vault CLI is a **fleet prerequisite, provisioned by MDM — it is NOT installed by the
plugin or by the Windows `sandbox-dlp` installer** (which only ships WinFsp, the
`sandbox-dlp` service, and the `secrets-guard` binary). Push the CLI and its credentials
the same way you push `managed-settings.json`:

- **Keeper:** install the `ksm` CLI on `PATH` (MDM package; on Windows the Inno-Setup EXE
  `KeeperSecurity.KeeperSecretsManager`). Redeem a one-time token once, store the resulting
  base64 config, and push it as `KSM_CONFIG` via `env`.
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
