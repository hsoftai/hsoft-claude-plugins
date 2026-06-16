//go:build !linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateConfigDir redirects os.UserConfigDir (used for the recovery journal) to a
// temp dir so tests never touch the real config dir.
func isolateConfigDir(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())            // darwin: UserConfigDir = $HOME/Library/Application Support
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // linux-ish fallbacks
	t.Setenv("AppData", t.TempDir())         // windows
}

func TestRenderFiles_InPlaceAndRestore(t *testing.T) {
	isolateConfigDir(t)
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	const orig = "PASSWORD=op://v/i/p\nPORT=8080\n"
	if err := os.WriteFile(p, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	files := []refFile{{path: p, refs: []string{"op://v/i/p"}}}
	values := map[string]string{"op://v/i/p": "SECRETVAL"}

	restore, err := renderFiles(files, values)
	if err != nil {
		t.Fatal(err)
	}
	// During the command the real file holds the value.
	if got, _ := os.ReadFile(p); string(got) != "PASSWORD=SECRETVAL\nPORT=8080\n" {
		t.Fatalf("not rendered in place: %q", got)
	}
	restore()
	// After restore the real file holds the reference again.
	if got, _ := os.ReadFile(p); string(got) != orig {
		t.Fatalf("not restored: %q", got)
	}
}

func TestRecoverSandboxJournals_AfterCrash(t *testing.T) {
	isolateConfigDir(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	const orig = "token: op://v/i/p\nnote: plain\n"
	if err := os.WriteFile(p, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	files := []refFile{{path: p, refs: []string{"op://v/i/p"}}}
	values := map[string]string{"op://v/i/p": "SECRETVAL"}

	// Render but DROP the restore func — simulates a SIGKILL before restore runs.
	if _, err := renderFiles(files, values); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); !strings.Contains(string(got), "SECRETVAL") {
		t.Fatalf("expected the value on disk after a crash, got %q", got)
	}
	// Crash recovery (what SessionStart runs) must restore the original reference.
	recoverSandboxJournals()
	if got, _ := os.ReadFile(p); string(got) != orig {
		t.Fatalf("recovery did not restore the original: %q", got)
	}
	// And no journal is left behind.
	d, _ := sandboxJournalDir()
	if m, _ := filepath.Glob(filepath.Join(d, "j-*.json")); len(m) != 0 {
		t.Fatalf("journal not cleaned up: %v", m)
	}
}

// An escaped reference in a file is rendered to its literal form (backslash stripped),
// never the value.
func TestRenderFiles_Escape(t *testing.T) {
	isolateConfigDir(t)
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte("A=op://v/i/p\nB=\\op://keep/it\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	files := []refFile{{path: p, refs: []string{"op://v/i/p"}}}
	restore, _ := renderFiles(files, map[string]string{"op://v/i/p": "VAL"})
	got, _ := os.ReadFile(p)
	if string(got) != "A=VAL\nB=op://keep/it\n" {
		t.Fatalf("escape/render wrong: %q", got)
	}
	restore()
}
