package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hsoftai/hsoft-claude-plugins/internal/hook"
)

// dumpEnvProbe writes a diagnostic snapshot of what THIS hook invocation receives
// — so we can determine, from a real Cowork session, the environment in which the
// COMMAND will run (the VM) vs where the hook runs (the host). Enabled only when
// SG_DEBUG_ENV is set. Best-effort, never affects the hook decision.
//
// It answers: does the hook see CLAUDE_CODE_ENTRYPOINT=cowork? Is its cwd /
// transcript_path the host view (local-agent-mode-sessions) or the VM view
// (/sessions/.../mnt/outputs)? Which lets the hook build the VM command correctly.
func dumpEnvProbe(in hook.Input) {
	if os.Getenv("SG_DEBUG_ENV") == "" {
		return
	}

	// Collect the env vars that distinguish Code (host) from Cowork (host↔VM).
	envInteresting := map[string]string{}
	for _, kv := range os.Environ() {
		i := strings.IndexByte(kv, '=')
		if i < 0 {
			continue
		}
		k, v := kv[:i], kv[i+1:]
		up := strings.ToUpper(k)
		if strings.HasPrefix(up, "CLAUDE") || strings.HasPrefix(up, "COWORK") ||
			strings.HasPrefix(up, "ANTHROPIC") || up == "AI_AGENT" ||
			strings.HasPrefix(up, "SYSTEMD") || up == "INVOCATION_ID" || up == "JOURNAL_STREAM" ||
			up == "PWD" || up == "HOME" {
			envInteresting[k] = v
		}
	}
	host, _ := os.Hostname()
	pwd, _ := os.Getwd()
	hasMarker := func(s string) string {
		switch {
		case strings.Contains(s, "/sessions/"):
			return "vm(/sessions/)"
		case strings.Contains(s, "local-agent-mode-sessions"):
			return "host(local-agent-mode-sessions)"
		default:
			return "neither"
		}
	}

	snapshot := map[string]any{
		"goos":                  runtime.GOOS,
		"hostname":              host,
		"hook_event":            in.HookEventName,
		"session_id":            in.SessionID,
		"stdin_cwd":             in.Cwd,
		"stdin_transcript_path": in.TranscriptPath,
		"process_pwd":           pwd,
		"marker_stdin_cwd":      hasMarker(in.Cwd),
		"marker_transcript":     hasMarker(in.TranscriptPath),
		"marker_process_pwd":    hasMarker(pwd),
		"entrypoint":            os.Getenv("CLAUDE_CODE_ENTRYPOINT"),
		"env":                   envInteresting,
	}
	data, _ := json.MarshalIndent(snapshot, "", "  ")
	data = append(data, '\n')

	// Write to several candidate locations so it is readable from whichever side
	// the hook runs on (host home/tmp, and the cwd in case it is the shared mount).
	name := "secrets-guard-envprobe-" + sanitizeProbe(in.HookEventName) + ".json"
	targets := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		targets = append(targets, filepath.Join(home, name))
	}
	targets = append(targets, filepath.Join(os.TempDir(), name))
	if in.Cwd != "" {
		targets = append(targets, filepath.Join(in.Cwd, name))
	}
	if pwd != "" {
		targets = append(targets, filepath.Join(pwd, name))
	}
	for _, t := range targets {
		_ = os.WriteFile(t, data, 0o600)
	}
}

func sanitizeProbe(s string) string {
	if s == "" {
		return "unknown"
	}
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, s)
}
