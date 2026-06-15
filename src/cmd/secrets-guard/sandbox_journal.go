package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// On macOS/Windows there are no mount namespaces, so the sandbox renders ref-files
// IN PLACE (writes the real values), runs the command, and restores the originals.
// To survive a hard kill (SIGKILL/power loss) between render and restore, it writes
// a RECOVERY JOURNAL of the original content BEFORE touching the files. The journal
// holds the original, reference-bearing content (op://… paths) — NOT secret values —
// so it is safe at rest (0600, in the host-only config dir). SessionStart restores
// any journal a previous run left behind.

type journalEntry struct {
	Path     string `json:"path"`
	Original string `json:"original"`
}

func sandboxJournalDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", herr
		}
		base = filepath.Join(home, ".config")
	}
	d := filepath.Join(base, "secrets-guard", "sandbox-journal")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, nil
}

// newJournal persists the original (reference-bearing) content of the files about to
// be rendered, returning the journal path. Written BEFORE any value hits disk.
func newJournal(entries []journalEntry) string {
	if len(entries) == 0 {
		return ""
	}
	d, err := sandboxJournalDir()
	if err != nil {
		return ""
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	p := filepath.Join(d, "j-"+hex.EncodeToString(b)+".json")
	data, _ := json.Marshal(entries)
	if os.WriteFile(p, data, 0o600) != nil {
		return ""
	}
	return p
}

func removeJournal(p string) {
	if p != "" {
		_ = os.Remove(p)
	}
}

// restoreJournalFile writes each entry's original content back (only when the file
// currently differs), then removes the journal. Used for the normal post-command
// restore and for crash recovery.
func restoreJournalFile(p string) {
	data, err := os.ReadFile(p)
	if err != nil {
		_ = os.Remove(p)
		return
	}
	var entries []journalEntry
	if json.Unmarshal(data, &entries) != nil {
		_ = os.Remove(p)
		return
	}
	for _, e := range entries {
		if cur, err := os.ReadFile(e.Path); err == nil && string(cur) == e.Original {
			continue // already the original — nothing to undo
		}
		_ = os.WriteFile(e.Path, []byte(e.Original), 0o600) // truncate-write keeps perms
	}
	_ = os.Remove(p)
}

// recoverSandboxJournals restores any journals a killed sandbox left behind. Called
// at SessionStart so a crash never leaves a rendered (value-bearing) file on disk.
func recoverSandboxJournals() {
	d, err := sandboxJournalDir()
	if err != nil {
		return
	}
	matches, _ := filepath.Glob(filepath.Join(d, "j-*.json"))
	for _, p := range matches {
		restoreJournalFile(p)
	}
}
