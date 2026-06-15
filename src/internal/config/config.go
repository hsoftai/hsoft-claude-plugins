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

	// Cowork mode: the agent's commands run in an isolated VM with no vault CLI.
	// Resolution happens on the host; values are delivered to the VM over the
	// sealed-box disk channel (internal/cowork) — the only host↔VM channel.
	ExecutionMode   string // auto | local | cowork
	CoworkSpool     string // host-side path of the shared `outputs` mount (= CLAUDE_PROJECT_DIR)
	CoworkIsolate   bool   // wrap the VM child in a user/pid/mount namespace (unshare)
	CoworkRefPolicy string // enforce (default) | audit — allowlist refs the host approved

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
		CoworkRefPolicy:     "enforce",
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

	c.ExecutionMode = oneOf(env(prefix+"EXECUTION_MODE"), c.ExecutionMode, "auto", "local", "cowork")
	c.CoworkSpool = strings.TrimSpace(env(prefix + "COWORK_SPOOL"))
	c.CoworkIsolate = boolOr(env(prefix+"COWORK_ISOLATE"), false)
	c.CoworkRefPolicy = oneOf(env(prefix+"COWORK_REF_POLICY"), c.CoworkRefPolicy, "audit", "enforce")

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
