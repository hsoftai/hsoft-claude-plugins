package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/hsoftai/hsoft-claude-plugins/internal/hook"
)

// dumpEnvProbe writes a diagnostic snapshot of what THIS hook invocation receives
// — so we can determine, from a real Cowork session, the environment in which the
// COMMAND will run (the VM) vs where the hook runs (the host). Best-effort, never
// affects the hook decision.
//
// It answers: does the hook see CLAUDE_CODE_ENTRYPOINT=cowork? Is its cwd /
// transcript_path the host view (local-agent-mode-sessions) or the VM view
// (/sessions/.../mnt/outputs)? Which lets the hook build the VM command correctly.
//
// Triggering is intentionally robust so it does NOT depend on env propagation into
// the Cowork host hook (which the SessionStart `env` block does not reliably do):
//   - env SG_DEBUG_ENV set, OR
//   - a host sentinel file ~/.claude/sg-debug-env exists, OR
//   - a .sg-debug sentinel exists in the hook's cwd.
//
// Output is written to every readable candidate (host home/tmp, cwd, process cwd)
// AND to any discovered Cowork "outputs" spool, so it is readable from whichever
// side the hook runs on without a session restart.
func dumpEnvProbe(in hook.Input) {
	if !probeEnabled(in) {
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
		// Never capture identity/credential material — only environment-shape signals.
		if strings.Contains(up, "TOKEN") || strings.Contains(up, "SECRET") ||
			strings.Contains(up, "KEY") || strings.Contains(up, "EMAIL") ||
			strings.Contains(up, "UUID") || strings.Contains(up, "ACCOUNT") ||
			strings.Contains(up, "ORGANIZATION") || strings.Contains(up, "SCOPES") ||
			strings.Contains(up, "TAGGED") || strings.Contains(up, "PASS") {
			continue
		}
		if strings.HasPrefix(up, "CLAUDE") || strings.HasPrefix(up, "COWORK") ||
			strings.HasPrefix(up, "ANTHROPIC") || up == "AI_AGENT" ||
			strings.HasPrefix(up, "SYSTEMD") || up == "INVOCATION_ID" || up == "JOURNAL_STREAM" ||
			up == "PWD" || up == "HOME" || up == "USER" || up == "LOGNAME" {
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
		"goarch":                runtime.GOARCH,
		"uid":                   os.Getuid(),
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
		"cgroup1":               readFirst("/proc/1/cgroup", 400),
		"env":                   envInteresting,
	}
	data, _ := json.MarshalIndent(snapshot, "", "  ")
	data = append(data, '\n')

	// Write to every candidate location so it is readable from whichever side the
	// hook runs on (host home/tmp, cwd, process cwd) AND every Cowork outputs spool
	// we can discover (host-side and VM-side).
	name := "secrets-guard-envprobe-" + sanitizeProbe(in.HookEventName) + ".json"
	seen := map[string]bool{}
	write := func(dir string) {
		if dir == "" {
			return
		}
		t := filepath.Join(dir, name)
		if seen[t] {
			return
		}
		seen[t] = true
		_ = os.WriteFile(t, data, 0o600)
	}

	if home, err := os.UserHomeDir(); err == nil {
		write(home)
	}
	write(os.TempDir())
	write(in.Cwd)
	write(pwd)
	for _, sp := range discoverSpools() {
		write(sp)
	}
}

// probeEnabled reports whether the diagnostic should run, using cheap checks only
// (at most a few stat calls) so a normal Claude Code session pays nothing.
func probeEnabled(in hook.Input) bool {
	if os.Getenv("SG_DEBUG_ENV") != "" {
		return true
	}
	if home, err := os.UserHomeDir(); err == nil {
		if fileExistsProbe(filepath.Join(home, ".claude", "sg-debug-env")) {
			return true
		}
	}
	if in.Cwd != "" && fileExistsProbe(filepath.Join(in.Cwd, ".sg-debug")) {
		return true
	}
	return false
}

// discoverSpools returns Cowork "outputs" spool directories, newest first, looking
// both at the host layout (~/Library/Application Support/Claude/local-agent-mode-sessions)
// and the VM layout (/sessions/*/mnt/outputs). Only called once the probe fires.
func discoverSpools() []string {
	type cand struct {
		path string
		mod  int64
	}
	var cands []cand
	add := func(p string) {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			cands = append(cands, cand{p, fi.ModTime().UnixNano()})
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		base := filepath.Join(home, "Library", "Application Support", "Claude", "local-agent-mode-sessions")
		for _, p := range findOutputsDirs(base, 5) {
			add(p)
		}
	}
	for _, p := range findOutputsDirs("/sessions", 4) {
		add(p)
	}

	sort.Slice(cands, func(i, j int) bool { return cands[i].mod > cands[j].mod })
	out := make([]string, 0, len(cands))
	for i, c := range cands {
		if i >= 4 { // cap: only the few most-recent sessions
			break
		}
		out = append(out, c.path)
	}
	return out
}

// findOutputsDirs does a bounded descent under base collecting directories named
// "outputs". It never descends into an "outputs" dir's contents and stops at the
// given depth, so it does not scan large upload/project trees.
func findOutputsDirs(base string, maxDepth int) []string {
	var found []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			child := filepath.Join(dir, name)
			if name == "outputs" {
				found = append(found, child)
				continue // do not descend into outputs contents
			}
			if strings.HasPrefix(name, ".") && name != "." {
				continue // skip hidden trees (.git, etc.)
			}
			if name == "uploads" || name == "projects" || name == "node_modules" {
				continue // known-large, never holds the spool
			}
			walk(child, depth+1)
		}
	}
	walk(base, 0)
	return found
}

func readFirst(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, n)
	r, _ := f.Read(buf)
	return strings.TrimSpace(string(buf[:r]))
}

func fileExistsProbe(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
