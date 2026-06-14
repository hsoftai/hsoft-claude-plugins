package hook

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hsoftai/hsoft-claude-plugins/internal/detect"
	"github.com/hsoftai/hsoft-claude-plugins/internal/redact"
)

// TestMain isolates the per-session ledger (internal/seen) to a temp dir.
func TestMain(m *testing.M) {
	d, _ := os.MkdirTemp("", "sg-hook-test")
	os.Setenv("TMPDIR", d)
	code := m.Run()
	os.RemoveAll(d)
	os.Exit(code)
}

// fakeResolver replaces any vault reference (scheme://...) with a fixed value,
// standing in for a real Keeper/1Password provider in unit tests.
type fakeResolver struct{ value string }

var refRe = regexp.MustCompile(`(?i)(?:keeper|op|akv)://[^\s"']+`)

func (f fakeResolver) ResolveString(s string) (string, []string, error) {
	matches := refRe.FindAllString(s, -1)
	if len(matches) == 0 {
		return s, nil, nil
	}
	vals := make([]string, len(matches))
	for i := range vals {
		vals[i] = f.value
	}
	return refRe.ReplaceAllString(s, f.value), vals, nil
}

func (f fakeResolver) ResolveValues(refs []string) []string {
	out := make([]string, 0, len(refs))
	for range refs {
		out = append(out, f.value)
	}
	return out
}

func (f fakeResolver) FindRefs(s string) []string { return refRe.FindAllString(s, -1) }

// noopCache makes Scan unavailable so tests exercise the re-resolution fallback
// (and never spawn a real daemon).
type noopCache struct{}

func (noopCache) Add(string, []string)                     {}
func (noopCache) Scan(string, string) (bool, string, bool) { return false, "", false }
func (noopCache) Shutdown(string)                          {}

func newHandler(cfg Config) *Handler {
	eng := detect.New()
	return NewHandler(cfg, eng, redact.New(eng), fakeResolver{value: "RESOLVED_SECRET"}, noopCache{}, "/opt/sg/bin/secrets-guard")
}

func defaultCfg() Config {
	return Config{
		BlockOnPromptSecret: true,
		ToolInputPolicy:     "deny",
		ToolOutputMode:      "redact",
	}
}

// --- UserPromptSubmit ---

func TestUserPromptSubmit_BlocksPlaintextSecret(t *testing.T) {
	h := newHandler(defaultCfg())
	out := h.Handle(Input{
		HookEventName: "UserPromptSubmit",
		Prompt:        "connect to aws with AKIAIOSFODNN7EXAMPLE",
	})
	if out.Decision != "block" {
		t.Fatalf("expected block, got %+v", out)
	}
	if !strings.Contains(strings.ToLower(out.SystemMessage), "keeper") &&
		!strings.Contains(strings.ToLower(out.SystemMessage), "bóveda") {
		t.Fatalf("system message should guide to a vault reference, got %q", out.SystemMessage)
	}
}

func TestUserPromptSubmit_AllowsCleanPrompt(t *testing.T) {
	h := newHandler(defaultCfg())
	out := h.Handle(Input{HookEventName: "UserPromptSubmit", Prompt: "refactor the auth module"})
	if out.Decision == "block" {
		t.Fatalf("clean prompt must not be blocked, got %+v", out)
	}
}

func TestUserPromptSubmit_AllowsVaultReference(t *testing.T) {
	h := newHandler(defaultCfg())
	out := h.Handle(Input{HookEventName: "UserPromptSubmit", Prompt: "use op://vault/item/password"})
	if out.Decision == "block" {
		t.Fatalf("vault reference must not be blocked, got %+v", out)
	}
}

func TestUserPromptSubmit_DisabledDoesNotBlock(t *testing.T) {
	cfg := defaultCfg()
	cfg.BlockOnPromptSecret = false
	h := newHandler(cfg)
	out := h.Handle(Input{HookEventName: "UserPromptSubmit", Prompt: "AKIAIOSFODNN7EXAMPLE"})
	if out.Decision == "block" {
		t.Fatalf("blocking disabled, must not block, got %+v", out)
	}
}

// --- PreToolUse ---

func TestPreToolUse_DeniesPlaintextSecret(t *testing.T) {
	h := newHandler(defaultCfg())
	out := h.Handle(Input{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     json.RawMessage(`{"command":"export AWS_KEY=AKIAIOSFODNN7EXAMPLE"}`),
	})
	if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("expected deny, got %+v", out.HookSpecificOutput)
	}
}

func TestPreToolUse_ResolvesVaultReference(t *testing.T) {
	cfg := defaultCfg()
	cfg.ToolOutputMode = "off" // isolate injection from output wrapping
	h := newHandler(cfg)
	out := h.Handle(Input{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     json.RawMessage(`{"command":"export DB=op://vault/db/password"}`),
	})
	if out.HookSpecificOutput == nil || len(out.HookSpecificOutput.UpdatedInput) == 0 {
		t.Fatalf("expected updatedInput with resolved value, got %+v", out.HookSpecificOutput)
	}
	var ti struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(out.HookSpecificOutput.UpdatedInput, &ti); err != nil {
		t.Fatalf("updatedInput not valid: %v", err)
	}
	if !strings.Contains(ti.Command, "RESOLVED_SECRET") {
		t.Fatalf("reference not resolved: %q", ti.Command)
	}
	if strings.Contains(ti.Command, "op://") {
		t.Fatalf("reference should be gone: %q", ti.Command)
	}
}

// A command that itself resolves a reference (op read, ksm notation, …) must
// keep the reference LITERAL — injecting the value would break it. The value is
// still resolved internally (tracked) so the command's output can be redacted.
func TestPreToolUse_VaultResolverCommandKeepsReference(t *testing.T) {
	cfg := defaultCfg()
	cfg.ToolOutputMode = "off" // isolate from output wrapping
	h := newHandler(cfg)
	out := h.Handle(Input{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     json.RawMessage(`{"command":"op read \"op://Employee/test-claude/password\""}`),
	})
	// No command rewrite (reference kept), but tracked internally for redaction.
	if out.HookSpecificOutput != nil && len(out.HookSpecificOutput.UpdatedInput) > 0 {
		t.Fatalf("op read must keep the reference, got rewrite %+v", out.HookSpecificOutput)
	}
	if h.Last.Action != "track" {
		t.Fatalf("expected internal tracking (action=track), got %q", h.Last.Action)
	}
	if h.Last.Count == 0 {
		t.Fatalf("reference should have been resolved internally for redaction")
	}
}

// A backslash escapes a single occurrence: the value is not injected, the
// reference is kept (without the backslash), and it is still tracked.
func TestPreToolUse_BackslashEscapeKeepsReference(t *testing.T) {
	cfg := defaultCfg()
	cfg.ToolOutputMode = "off"
	h := newHandler(cfg)
	out := h.Handle(Input{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     json.RawMessage(`{"command":"echo \\op://vault/db/password > script.sh"}`),
	})
	if out.HookSpecificOutput == nil || len(out.HookSpecificOutput.UpdatedInput) == 0 {
		t.Fatalf("expected a rewrite that strips the backslash, got %+v", out.HookSpecificOutput)
	}
	var ti struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(out.HookSpecificOutput.UpdatedInput, &ti); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ti.Command, "RESOLVED_SECRET") {
		t.Fatalf("escaped reference must not be injected: %q", ti.Command)
	}
	if !strings.Contains(ti.Command, "op://vault/db/password") {
		t.Fatalf("reference should remain literal: %q", ti.Command)
	}
	if strings.Contains(ti.Command, `\op://`) {
		t.Fatalf("opt-out backslash should be stripped: %q", ti.Command)
	}
}

// command_references=keep makes every occurrence stay literal while still being
// tracked for output redaction.
func TestPreToolUse_CommandReferencesKeep(t *testing.T) {
	cfg := defaultCfg()
	cfg.ToolOutputMode = "off"
	cfg.CommandReferences = "keep"
	h := newHandler(cfg)
	out := h.Handle(Input{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     json.RawMessage(`{"command":"echo op://vault/db/password"}`),
	})
	if out.HookSpecificOutput != nil && len(out.HookSpecificOutput.UpdatedInput) > 0 {
		t.Fatalf("keep mode must not rewrite the command, got %+v", out.HookSpecificOutput)
	}
	if h.Last.Action != "track" {
		t.Fatalf("expected action=track, got %q", h.Last.Action)
	}
}

func TestPreToolUse_AllowsCleanCommand(t *testing.T) {
	cfg := defaultCfg()
	cfg.ToolOutputMode = "off" // no wrapping, just check it is not denied
	h := newHandler(cfg)
	out := h.Handle(Input{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     json.RawMessage(`{"command":"go test ./..."}`),
	})
	if out.HookSpecificOutput != nil && out.HookSpecificOutput.PermissionDecision == "deny" {
		t.Fatalf("clean command must not be denied, got %+v", out.HookSpecificOutput)
	}
}

func TestPreToolUse_WrapsBashOutputInRedactMode(t *testing.T) {
	h := newHandler(defaultCfg()) // ToolOutputMode = redact
	out := h.Handle(Input{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     json.RawMessage(`{"command":"cat config.txt"}`),
	})
	if out.HookSpecificOutput == nil || len(out.HookSpecificOutput.UpdatedInput) == 0 {
		t.Fatalf("expected wrapped updatedInput, got %+v", out.HookSpecificOutput)
	}
	var ti struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(out.HookSpecificOutput.UpdatedInput, &ti); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ti.Command, "redact-stream") {
		t.Fatalf("command not wrapped: %q", ti.Command)
	}
	if !strings.Contains(ti.Command, "cat config.txt") {
		t.Fatalf("original command lost: %q", ti.Command)
	}
}

// File-writing tools keep the reference in the file (option A): the value is
// never injected, so it never lands in plaintext on disk or in the result.
func TestPreToolUse_WriteKeepsReference(t *testing.T) {
	h := newHandler(defaultCfg())
	out := h.Handle(Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput:     json.RawMessage(`{"file_path":".env","content":"DB_PASSWORD=op://vault/db/password"}`),
	})
	if out.HookSpecificOutput != nil && len(out.HookSpecificOutput.UpdatedInput) > 0 {
		t.Fatalf("Write must keep the reference (no injection), got %+v", out.HookSpecificOutput)
	}
}

func TestPreToolUse_DoesNotWrapNonBash(t *testing.T) {
	h := newHandler(defaultCfg())
	out := h.Handle(Input{
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     json.RawMessage(`{"file_path":"/etc/hosts"}`),
	})
	if out.HookSpecificOutput != nil && len(out.HookSpecificOutput.UpdatedInput) > 0 {
		t.Fatalf("non-Bash tool must not be wrapped, got %+v", out.HookSpecificOutput)
	}
}

// --- PostToolUse ---

// PostToolUse cannot rewrite output in Claude Code 2.1.x, so a leaked secret in
// a tool result is withheld (blocked). For Bash this is a safety net; Bash
// output is normally already redacted by the PreToolUse wrap.
func TestPostToolUse_BlocksLeakedSecret(t *testing.T) {
	h := newHandler(defaultCfg()) // redact mode
	out := h.Handle(Input{
		HookEventName: "PostToolUse",
		ToolName:      "Read",
		ToolResponse:  json.RawMessage(`"the key is AKIAIOSFODNN7EXAMPLE done"`),
	})
	if out.Decision != "block" {
		t.Fatalf("expected block on leaked secret, got %+v", out)
	}
}

func TestPostToolUse_PassthroughCleanOutput(t *testing.T) {
	h := newHandler(defaultCfg())
	out := h.Handle(Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolResponse:  json.RawMessage(`"all tests passed"`),
	})
	if out.Decision == "block" {
		t.Fatalf("clean output must not be blocked, got %+v", out)
	}
}

func TestPostToolUse_BlockMode(t *testing.T) {
	cfg := defaultCfg()
	cfg.ToolOutputMode = "block"
	h := newHandler(cfg)
	out := h.Handle(Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolResponse:  json.RawMessage(`"leaked AKIAIOSFODNN7EXAMPLE"`),
	})
	if out.Decision != "block" {
		t.Fatalf("expected block decision, got %+v", out)
	}
}

func TestPostToolUse_OffMode(t *testing.T) {
	cfg := defaultCfg()
	cfg.ToolOutputMode = "off"
	h := newHandler(cfg)
	out := h.Handle(Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolResponse:  json.RawMessage(`"leaked AKIAIOSFODNN7EXAMPLE"`),
	})
	if out.HookSpecificOutput != nil && out.HookSpecificOutput.UpdatedToolOutput != "" {
		t.Fatalf("off mode must not modify output, got %+v", out.HookSpecificOutput)
	}
	if out.Decision == "block" {
		t.Fatalf("off mode must not block, got %+v", out)
	}
}
