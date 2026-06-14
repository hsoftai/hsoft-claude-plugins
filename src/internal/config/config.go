// Package config loads secrets-guard runtime options. Options are supplied by
// Claude Code as CLAUDE_PLUGIN_OPTION_<KEY> environment variables, which the
// admin sets centrally in managed-settings.json (env block) or via the
// plugin's userConfig. Every option has a safe default.
package config

import (
	"strconv"
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

	// Broker mode (Cowork): resolution happens on the host and resolved values
	// are delivered to the VM over a network broker, used only in memory.
	ExecutionMode   string // auto | local | broker
	CoworkSpool     string // path to the shared `outputs` mount (host or VM side)
	BrokerHost      string // IP the host broker binds/advertises on the vmnet bridge
	BrokerPort      int    // TCP port for the broker (0 = default 8771)
	BrokerRefPolicy string // enforce (default) | audit — allowlist refs the host observed
}

// DefaultBrokerPort is used when broker_port is unset.
const DefaultBrokerPort = 8771

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
		BrokerPort:          DefaultBrokerPort,
		BrokerRefPolicy:     "enforce",
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

	c.ExecutionMode = oneOf(env(prefix+"EXECUTION_MODE"), c.ExecutionMode, "auto", "local", "broker")
	c.CoworkSpool = env(prefix + "COWORK_SPOOL")
	c.BrokerHost = env(prefix + "BROKER_HOST")
	c.BrokerPort = intOr(env(prefix+"BROKER_PORT"), c.BrokerPort)
	c.BrokerRefPolicy = oneOf(env(prefix+"BROKER_REF_POLICY"), c.BrokerRefPolicy, "audit", "enforce")
	return c
}

func intOr(v string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 && n <= 65535 {
		return n
	}
	return def
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
