package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDiscoverKeeperINI verifies that an existing keeper.ini in a standard per-user
// location is found (and that ~/.keeper/keeper.ini takes precedence over ~/keeper.ini).
func TestDiscoverKeeperINI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows

	if got := discoverKeeperINI(); got != "" {
		t.Fatalf("no keeper.ini present: expected \"\", got %q", got)
	}

	plain := filepath.Join(home, "keeper.ini")
	if err := os.WriteFile(plain, []byte("[_default]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := discoverKeeperINI(); got != plain {
		t.Fatalf("got %q, want %q", got, plain)
	}

	dir := filepath.Join(home, ".keeper")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pref := filepath.Join(dir, "keeper.ini")
	if err := os.WriteFile(pref, []byte("[_default]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := discoverKeeperINI(); got != pref {
		t.Fatalf("~/.keeper/keeper.ini must win: got %q, want %q", got, pref)
	}
}

// TestKeeperINIArgs covers the precedence: KSM_CONFIG > KSM_INI_FILE > auto-discovery.
func TestKeeperINIArgs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	// KSM_CONFIG (base64) takes precedence: no INI flag at all.
	t.Setenv("KSM_CONFIG", "base64data")
	t.Setenv("KSM_INI_FILE", "/should/be/ignored")
	if got := keeperINIArgs(); got != nil {
		t.Fatalf("with KSM_CONFIG set, expected nil, got %v", got)
	}

	// Explicit KSM_INI_FILE is used verbatim.
	t.Setenv("KSM_CONFIG", "")
	t.Setenv("KSM_INI_FILE", "/custom/keeper.ini")
	if got := keeperINIArgs(); len(got) != 2 || got[0] != "--ini-file" || got[1] != "/custom/keeper.ini" {
		t.Fatalf("KSM_INI_FILE path: got %v", got)
	}

	// Neither env set: auto-discover the user's keeper.ini.
	t.Setenv("KSM_INI_FILE", "")
	plain := filepath.Join(home, "keeper.ini")
	if err := os.WriteFile(plain, []byte("[_default]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := keeperINIArgs(); len(got) != 2 || got[0] != "--ini-file" || got[1] != plain {
		t.Fatalf("auto-discovery: got %v, want [--ini-file %s]", got, plain)
	}

	// No env and no file present: nil (let ksm use its own current-directory lookup).
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("USERPROFILE", empty)
	if got := keeperINIArgs(); got != nil {
		t.Fatalf("no config anywhere: expected nil, got %v", got)
	}
}
