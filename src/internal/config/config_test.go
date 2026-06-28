package config

import "testing"

func TestLoad_Defaults(t *testing.T) {
	c := Load(func(string) string { return "" })
	if c.VaultProvider != "auto" {
		t.Errorf("VaultProvider default = %q, want auto", c.VaultProvider)
	}
	if !c.BlockOnPromptSecret {
		t.Errorf("BlockOnPromptSecret default should be true")
	}
	if c.ToolInputPolicy != "deny" {
		t.Errorf("ToolInputPolicy default = %q, want deny", c.ToolInputPolicy)
	}
	if c.ToolOutputMode != "redact" {
		t.Errorf("ToolOutputMode default = %q, want redact", c.ToolOutputMode)
	}
	// The redaction guard is on by default.
	if !c.PreloadEnabled() {
		t.Errorf("PreloadEnabled should be true by default")
	}
	// Fail-closed policy defaults to auto (fail closed only where the service runs).
	if c.GuardRequired != "auto" {
		t.Errorf("GuardRequired default = %q, want auto", c.GuardRequired)
	}
	// Onboarding gate defaults to on (block prompts until a vault is configured).
	if c.RequireVault != "on" {
		t.Errorf("RequireVault default = %q, want on", c.RequireVault)
	}
}

func TestLoad_RequireVault(t *testing.T) {
	c := Load(func(k string) string {
		if k == "CLAUDE_PLUGIN_OPTION_REQUIRE_VAULT" {
			return "off"
		}
		return ""
	})
	if c.RequireVault != "off" {
		t.Errorf("RequireVault = %q, want off", c.RequireVault)
	}
	// invalid -> default on
	c = Load(func(k string) string {
		if k == "CLAUDE_PLUGIN_OPTION_REQUIRE_VAULT" {
			return "bogus"
		}
		return ""
	})
	if c.RequireVault != "on" {
		t.Errorf("invalid RequireVault should fall back to on, got %q", c.RequireVault)
	}
}

func TestLoad_GuardRequired(t *testing.T) {
	for _, v := range []string{"on", "off", "auto"} {
		c := Load(func(k string) string {
			if k == "CLAUDE_PLUGIN_OPTION_GUARD_REQUIRED" {
				return v
			}
			return ""
		})
		if c.GuardRequired != v {
			t.Errorf("GuardRequired = %q, want %q", c.GuardRequired, v)
		}
	}
	// Invalid falls back to auto.
	c := Load(func(k string) string {
		if k == "CLAUDE_PLUGIN_OPTION_GUARD_REQUIRED" {
			return "bogus"
		}
		return ""
	})
	if c.GuardRequired != "auto" {
		t.Errorf("invalid GuardRequired should fall back to auto, got %q", c.GuardRequired)
	}
}

func TestLoad_FromEnv(t *testing.T) {
	env := map[string]string{
		"CLAUDE_PLUGIN_OPTION_VAULT_PROVIDER":         "keeper",
		"CLAUDE_PLUGIN_OPTION_BLOCK_ON_PROMPT_SECRET": "false",
		"CLAUDE_PLUGIN_OPTION_TOOL_INPUT_POLICY":      "warn",
		"CLAUDE_PLUGIN_OPTION_TOOL_OUTPUT_MODE":       "block",
		"CLAUDE_PLUGIN_OPTION_AUDIT_LOG_PATH":         "/tmp/sg-audit.log",
	}
	c := Load(func(k string) string { return env[k] })

	if c.VaultProvider != "keeper" {
		t.Errorf("VaultProvider = %q", c.VaultProvider)
	}
	if c.BlockOnPromptSecret {
		t.Errorf("BlockOnPromptSecret should be false")
	}
	if c.ToolInputPolicy != "warn" {
		t.Errorf("ToolInputPolicy = %q", c.ToolInputPolicy)
	}
	if c.ToolOutputMode != "block" {
		t.Errorf("ToolOutputMode = %q", c.ToolOutputMode)
	}
	if c.AuditLogPath != "/tmp/sg-audit.log" {
		t.Errorf("AuditLogPath = %q", c.AuditLogPath)
	}
}

func TestLoad_InvalidEnumFallsBackToDefault(t *testing.T) {
	c := Load(func(k string) string {
		if k == "CLAUDE_PLUGIN_OPTION_TOOL_OUTPUT_MODE" {
			return "bogus"
		}
		return ""
	})
	if c.ToolOutputMode != "redact" {
		t.Errorf("invalid enum should fall back to redact, got %q", c.ToolOutputMode)
	}
}
