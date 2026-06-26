// Package config loads secrets-guard runtime options. Options are supplied by
// Claude Code as CLAUDE_PLUGIN_OPTION_<KEY> environment variables, which the
// admin sets centrally in managed-settings.json (env block) or via the
// plugin's userConfig. Every option has a safe default.
package config

import (
	"strings"
)

// Config is the resolved runtime configuration.
type Config struct {
	VaultProvider       string // auto | keeper | 1password
	OPAccount           string // 1Password account for multi-account machines
	BlockOnPromptSecret bool
	ToolInputPolicy     string // deny | redact | warn
	ToolOutputMode      string // redact | block | off
	CommandReferences   string // inject | keep (replace refs in Bash commands, or leave literal)
	CustomPatternsPath  string
	AllowlistPath       string
	AuditLogPath        string
	ShellTools          string // comma-separated extra shell tool names to wrap/redact

	// Cowork mode: the agent's commands run in an isolated VM with no vault CLI.
	// Resolution happens on the host; values are delivered to the VM over the
	// sealed-box disk channel (internal/cowork) — the only host↔VM channel.
	ExecutionMode   string // auto | local | cowork
	CoworkSpool     string // host-side path of the shared `outputs` mount (= CLAUDE_PROJECT_DIR)
	CoworkIsolate   bool   // wrap the VM child in a user/pid/mount namespace (unshare)
	CoworkRefPolicy string // audit (default) | enforce — resolve any token-authed ref, or only host-approved

	// Sandbox renders vault references (in env AND in matched files under cwd) into
	// real values inside an ephemeral per-command mount namespace, so apps that read
	// secrets from files — not just `secrets-guard run --env-file` — just work.
	//
	// DEFAULT off: the product's primary guarantee is that NO secret value reaches the
	// model's context (the redaction guard inspects every prompt and tool input/output).
	// Reference rendering is an opt-in convenience (`on`), not the default. Apps keep
	// reading their own local files (e.g. a `.env` with the real value); the model only
	// ever sees the redacted form. In Cowork the sandbox is the value-delivery channel,
	// so SandboxWrap forces it on there regardless of this setting.
	Sandbox      string // auto | on | off
	SandboxGlobs string // comma-separated globs overriding the default scan set

	// KernelDLP is DEPRECATED / no-op. The old WINDOWS sandbox-dlp / WinFsp service was
	// removed: secrets-guard runs entirely per-user (local ksm/op profile + in-memory
	// cache) and the sandbox, when enabled, uses the in-place renderer with a recovery
	// journal on every OS. Kept only for backward compatibility and ignored.
	KernelDLP        string // deprecated / no-op
	DLPInstallSource string // deprecated / no-op (no installer is downloaded any more)

	// PreloadSecrets controls the proactive full-vault redaction guard: at
	// SessionStart secrets-guard loads EVERY value the vault exposes to its
	// credential into the per-session in-memory cache (never disk), so any later
	// prompt, tool input, tool output, or file read containing one of those values
	// (in any encoding) is redacted or blocked before it can reach the model — even
	// if the value was never referenced this session. The values come from the user's
	// own local ksm/op profile and live only in the in-memory cache — on every platform,
	// Windows included (there is no system service). `auto` (default) and `on` enable it;
	// `off` disables it (only session-resolved values are guarded). It is the proactive
	// complement to the always-on backstop that blocks a value secrets-guard itself resolved.
	PreloadSecrets string // auto | on | off

	// GuardRequired controls FAIL-CLOSED behavior when the redaction guard cannot verify a
	// text because the vault values could not be loaded (the local ksm/op profile is not
	// initialized or failed to load).
	//   auto (default): degrade to the built-in pattern detector instead of blocking, so a
	//     machine without a working vault is not bricked.
	//   on: fail closed — block prompts, tool inputs and tool outputs that cannot be
	//     verified against the vault. For high-assurance fleets where every machine has a
	//     working profile and redaction is mandatory.
	//   off: never fail closed (always degrade to the detector).
	GuardRequired string // auto | on | off

	// IsCowork is the resolved detection: true when this process is the Cowork host
	// hook (the agent's commands run in the VM). Deterministic via
	// CLAUDE_CODE_IS_COWORK; an explicit execution_mode of cowork/local overrides it.
	IsCowork bool
}

// Getenv is the lookup function (os.Getenv in production, a map in tests).
type Getenv func(string) string

const prefix = "CLAUDE_PLUGIN_OPTION_"

// Load builds a Config from env, applying defaults and validating enums.
func Load(env Getenv) Config {
	c := Config{
		VaultProvider:       "auto",
		BlockOnPromptSecret: true,
		ToolInputPolicy:     "deny",
		ToolOutputMode:      "redact",
		CommandReferences:   "inject",
		ExecutionMode:       "auto",
		CoworkRefPolicy:     "audit",
		Sandbox:             "off",
		KernelDLP:           "auto",
		PreloadSecrets:      "auto",
		GuardRequired:       "auto",
	}

	c.VaultProvider = oneOf(env(prefix+"VAULT_PROVIDER"), c.VaultProvider, "auto", "keeper", "1password")
	c.OPAccount = env(prefix + "OP_ACCOUNT")
	c.BlockOnPromptSecret = boolOr(env(prefix+"BLOCK_ON_PROMPT_SECRET"), c.BlockOnPromptSecret)
	c.ToolInputPolicy = oneOf(env(prefix+"TOOL_INPUT_POLICY"), c.ToolInputPolicy, "deny", "redact", "warn")
	c.ToolOutputMode = oneOf(env(prefix+"TOOL_OUTPUT_MODE"), c.ToolOutputMode, "redact", "block", "off")
	c.CommandReferences = oneOf(env(prefix+"COMMAND_REFERENCES"), c.CommandReferences, "inject", "keep")
	c.CustomPatternsPath = env(prefix + "CUSTOM_PATTERNS_PATH")
	c.AllowlistPath = env(prefix + "ALLOWLIST_PATH")
	c.AuditLogPath = env(prefix + "AUDIT_LOG_PATH")
	c.ShellTools = strings.TrimSpace(env(prefix + "SHELL_TOOLS"))

	c.ExecutionMode = oneOf(env(prefix+"EXECUTION_MODE"), c.ExecutionMode, "auto", "local", "cowork")
	c.CoworkSpool = strings.TrimSpace(env(prefix + "COWORK_SPOOL"))
	c.CoworkIsolate = boolOr(env(prefix+"COWORK_ISOLATE"), false)
	c.CoworkRefPolicy = oneOf(env(prefix+"COWORK_REF_POLICY"), c.CoworkRefPolicy, "audit", "enforce")
	c.Sandbox = oneOf(env(prefix+"SANDBOX"), c.Sandbox, "auto", "on", "off")
	c.SandboxGlobs = strings.TrimSpace(env(prefix + "SANDBOX_GLOBS"))
	c.KernelDLP = oneOf(env(prefix+"KERNEL_DLP"), c.KernelDLP, "auto", "require", "off")
	c.DLPInstallSource = strings.TrimSpace(env(prefix + "DLP_INSTALL_SOURCE"))
	c.PreloadSecrets = oneOf(env(prefix+"PRELOAD_SECRETS"), c.PreloadSecrets, "auto", "on", "off")
	c.GuardRequired = oneOf(env(prefix+"GUARD_REQUIRED"), c.GuardRequired, "auto", "on", "off")

	// Detect the Cowork host hook (the agent's commands run in the VM). The detector
	// is deterministic — Claude Code sets CLAUDE_CODE_IS_COWORK=1 in the host hook's
	// environment (verified empirically; CLAUDE_CODE_ENTRYPOINT is "local-agent",
	// NOT "cowork", so it must not be used). An explicit execution_mode overrides.
	c.IsCowork = env("CLAUDE_CODE_IS_COWORK") == "1"
	switch c.ExecutionMode {
	case "cowork":
		c.IsCowork = true
	case "local":
		c.IsCowork = false
	}
	// The host spool is exactly CLAUDE_PROJECT_DIR in Cowork (the host view of the
	// shared `outputs` mount); auto-derive it so no manual config is needed.
	if c.CoworkSpool == "" {
		c.CoworkSpool = strings.TrimSpace(env("CLAUDE_PROJECT_DIR"))
	}
	return c
}

// SandboxWrap reports whether the hook should wrap a Bash command with the
// `secrets-guard sandbox` runner (transparent env + file + command rendering).
// hasVault indicates a local vault is present.
//
// The sandbox runs on every platform: Linux uses a private bind-mount (the value
// never touches the real disk), and macOS/Windows render files in place with a
// guaranteed restore. In Cowork the command runs in the Linux VM and the sandbox is
// the ONLY value-delivery channel, so it is always on there (checked first, before
// `off`). Otherwise: `off` (the default) disables it; `on` forces it; `auto` enables
// it wherever a vault can resolve.
func (c Config) SandboxWrap(hasVault bool) bool {
	if c.IsCowork {
		return true // Cowork delivers values only through the sandbox channel
	}
	if c.Sandbox == "off" {
		return false
	}
	if c.Sandbox == "on" {
		return true
	}
	return hasVault // auto
}

// PreloadEnabled reports whether the proactive full-vault redaction guard should
// run (preload every vault value into the session cache at SessionStart). `auto`
// and `on` enable it; the preloader itself no-ops when no vault/service can supply
// values, so `auto` is safe to leave on everywhere.
func (c Config) PreloadEnabled() bool { return c.PreloadSecrets != "off" }

func boolOr(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return def
	}
}

// oneOf returns v if it is one of allowed, otherwise def.
func oneOf(v, def string, allowed ...string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return def
}
