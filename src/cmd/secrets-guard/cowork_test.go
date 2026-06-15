package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// isolateHostDir points the Cowork host-only state dir at a temp dir for both the
// Linux (XDG_CONFIG_HOME) and macOS ($HOME/Library) layouts of os.UserConfigDir.
func isolateHostDir(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))
}

// writeExecRecordStamp rewrites an exec record's Stamp to age it (simulating time
// passing) without sleeping.
func ageExecRecord(t *testing.T, session, execID string, age time.Duration) {
	t.Helper()
	dir, err := coworkHostDir(session)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "exec-"+safeName(execID)+".json")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var rec execRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	rec.Stamp = time.Now().Add(-age).Unix()
	out, _ := json.Marshal(rec)
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Regression: a minted exec token that is never claimed by a fetch (the sandbox
// fast-path case — no references, so OnServed never fires) must NOT stay replayable
// for the full execTTL. Once past execFreshness it is refused by lookupExec and
// reaped, AND gcStaleExecs purges its lingering record from the host-only dir.
func TestLingeringExecToken_NotReplayableAfterFreshness(t *testing.T) {
	isolateHostDir(t)
	session := "sess-lingering"

	execID, _, _, ok := mintExec(session, []string{"op://v/i/p"})
	if !ok {
		t.Fatal("mintExec failed")
	}

	// Fresh: the legitimate VM can still resolve immediately after minting.
	if _, _, ok := lookupExec(session, execID); !ok {
		t.Fatal("a freshly minted exec must be valid")
	}

	// Simulate the command taking the fast path (no fetch) and time passing past the
	// freshness window — within the absolute TTL, so the OLD behavior would still
	// honor it (the bug). The fix must now refuse and reap it.
	ageExecRecord(t, session, execID, execFreshness+time.Minute)

	dir, _ := coworkHostDir(session)
	recPath := filepath.Join(dir, "exec-"+safeName(execID)+".json")
	if _, err := os.Stat(recPath); err != nil {
		t.Fatalf("precondition: record should still exist before lookup: %v", err)
	}

	if _, _, ok := lookupExec(session, execID); ok {
		t.Fatal("an un-fetched token past execFreshness must be refused (lingering-token replay)")
	}
	// lookupExec must also reap the refused record so it cannot be retried.
	if _, err := os.Stat(recPath); !os.IsNotExist(err) {
		t.Fatalf("refused exec record must be reaped on lookup, stat err=%v", err)
	}
}

// Regression: the daemon GC sweep reaps stale (never-fetched) exec records so the
// host-only dir cannot accumulate replayable tokens without bound, while leaving a
// fresh record untouched.
func TestGCStaleExecs_ReapsStaleKeepsFresh(t *testing.T) {
	isolateHostDir(t)
	session := "sess-gc"

	staleID, _, _, ok := mintExec(session, nil)
	if !ok {
		t.Fatal("mintExec(stale) failed")
	}
	freshID, _, _, ok := mintExec(session, nil)
	if !ok {
		t.Fatal("mintExec(fresh) failed")
	}
	ageExecRecord(t, session, staleID, execFreshness+time.Minute)

	gcStaleExecs(session)

	dir, _ := coworkHostDir(session)
	if _, err := os.Stat(filepath.Join(dir, "exec-"+safeName(staleID)+".json")); !os.IsNotExist(err) {
		t.Fatalf("stale exec record must be reaped by GC, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "exec-"+safeName(freshID)+".json")); err != nil {
		t.Fatalf("fresh exec record must survive GC: %v", err)
	}
	// The fresh record is still usable.
	if _, _, ok := lookupExec(session, freshID); !ok {
		t.Fatal("fresh exec must remain valid after GC")
	}
}
