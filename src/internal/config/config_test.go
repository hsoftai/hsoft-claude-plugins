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
	// The sandbox is OFF by default: the default product behavior is redaction-only
	// (inspect every prompt and tool I/O), not reference rendering.
	if c.Sandbox != "off" {
		t.Errorf("Sandbox default = %q, want off", c.Sandbox)
	}
	if c.SandboxWrap(true) {
		t.Errorf("SandboxWrap should be false by default (sandbox off, not Cowork)")
	}
	// The redaction guard is on by default.
	if !c.PreloadEnabled() {
		t.Errorf("PreloadEnabled should be true by default")
	}
}

func TestSandboxWrap_CoworkForcesOnEvenWhenOff(t *testing.T) {
	c := Load(func(string) string { return "" }) // Sandbox defaults to off
	c.IsCowork = true
	if !c.SandboxWrap(false) {
		t.Errorf("Cowork must force the sandbox on (its only value channel), even with sandbox=off")
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

func TestLoad_KernelDLP(t *testing.T) {
	// Default.
	c := Load(func(string) string { return "" })
	if c.KernelDLP != "auto" {
		t.Errorf("KernelDLP default = %q, want auto", c.KernelDLP)
	}
	// Valid override.
	c = Load(func(k string) string {
		if k == "CLAUDE_PLUGIN_OPTION_KERNEL_DLP" {
			return "require"
		}
		if k == "CLAUDE_PLUGIN_OPTION_DLP_INSTALL_SOURCE" {
			return "https://mirror.internal/sandbox-dlp"
		}
		return ""
	})
	if c.KernelDLP != "require" {
		t.Errorf("KernelDLP = %q, want require", c.KernelDLP)
	}
	if c.DLPInstallSource != "https://mirror.internal/sandbox-dlp" {
		t.Errorf("DLPInstallSource = %q", c.DLPInstallSource)
	}
	// Invalid enum falls back to default.
	c = Load(func(k string) string {
		if k == "CLAUDE_PLUGIN_OPTION_KERNEL_DLP" {
			return "bogus"
		}
		return ""
	})
	if c.KernelDLP != "auto" {
		t.Errorf("invalid KernelDLP should fall back to auto, got %q", c.KernelDLP)
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
