# Enforcing secrets-guard org-wide with managed-settings.json

`managed-settings.json` is the highest-precedence Claude Code settings layer: it
cannot be overridden by user or project settings. Deploy it via MDM (Intune,
Jamf, Kandji) to enforce secrets-guard across the organization.

Paths:

- macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
- Linux: `/etc/claude-code/managed-settings.json`
- Windows: `C:\ProgramData\ClaudeCode\managed-settings.json`

## How it works (local model — no WinFsp, no admin)

As of v0.6.0 secrets-guard runs **entirely per-user with no system service, no WinFsp
driver, and no administrator rights**. The redaction guard reads the user's own vault
through their local `ksm` / `op` profile (in its default location — it is not moved or
deleted), loads every value into a per-session in-memory cache at session start, and
redacts/blocks any of those values (in any encoding) in prompts and tool input/output
before they reach the model. If the vault profile isn't initialized, the guard degrades to
the built-in **secret-pattern detector** and never blocks normal use.

Prerequisite per user: the Keeper `ksm` CLI installed and a profile initialized
(`ksm profile init <token>`). That needs no admin. There is nothing machine-wide to
install; the previous `sandbox-dlp`/WinFsp service is no longer used.

`SANDBOX` stays `off` by default (redaction-only); `SANDBOX=on` enables in-place reference
rendering. `KERNEL_DLP` is deprecated/ignored. `GUARD_REQUIRED=on` makes the guard fail
closed if the vault is unavailable (strict); the default `auto` degrades to the detector.

## Windows one-shot enforcement script

On Windows you can write the managed file (and disable "bypass permissions" mode) in one
step with `installers/windows/enforce-secrets-guard.ps1`. It self-elevates and writes
`C:\ProgramData\ClaudeCode\managed-settings.json`. Download and run it on the target machine:

```powershell
powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://raw.githubusercontent.com/hsoftai/hsoft-claude-plugins/main/installers/windows/enforce-secrets-guard.ps1 -OutFile $env:TEMP\enforce-secrets-guard.ps1; & $env:TEMP\enforce-secrets-guard.ps1"
```

Each user then needs the `ksm` CLI with an initialized profile (no admin); the redaction
guard uses it directly. There is no WinFsp/service to install.

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
    "CLAUDE_PLUGIN_OPTION_SANDBOX": "off",
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

- **`SANDBOX`** (`auto` | `on` | `off`, **default `off`**) — the sandbox renders vault
  references (in the environment and in files under the working directory) into real
  values for the command's process only. It is **off by default**: the product's primary
  guarantee is redaction (no vault value reaches the model), not reference rendering, so
  apps just read their own local files (e.g. a `.env` holding the real value) and the
  model only ever sees the redacted form. `on` enables reference rendering; `auto`
  enables it wherever a vault can resolve. The redaction guard runs regardless of this
  setting.
- **`KERNEL_DLP`** (`auto` | `require` | `off`, **Windows only**) — selects the WinFsp
  `sandbox-dlp` service for per-process file rendering. `off` keeps the in-place
  renderer; `require` fails closed when the service is absent (never writes a value to
  disk); `auto` uses the service when present. Set `off` to disable the kernel-DLP path
  on Windows independently of `SANDBOX`.
- **`GUARD_REQUIRED`** (`auto` | `on` | `off`) — fail-closed policy when the redaction
  guard cannot verify a text (on Windows: the `sandbox-dlp` service is unreachable).
  `auto` (default) fails closed only where the service is actually running, so a machine
  where it was never provisioned (e.g. WinFsp not installed) degrades to the pattern
  detector instead of blocking every prompt and tool — an incomplete install does not
  brick the CLI. `on` always fails closed when the guard is unavailable (strict; for
  fleets that guarantee the service is installed). `off` never fails closed.
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
