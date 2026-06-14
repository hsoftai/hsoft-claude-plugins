package broker

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CTF-4 regression: a VM-planted symlink at the temp path must NOT redirect the
// host's bootstrap write to an arbitrary file (symlink-following write).
func TestWriteBootstrap_DoesNotFollowSymlink(t *testing.T) {
	spool := t.TempDir()
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "important.conf")
	if err := os.WriteFile(victim, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Pre-create the spool subdir and plant a symlink at the temp path the host
	// will use, pointing at the victim file (the VM can create, not delete).
	dir := filepath.Join(spool, spoolSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bs := Bootstrap{Session: "s", Plan: "A", DialAddr: "127.0.0.1:1", TokenB64: "dG9rZW4=", CertFP: "x", TTLUnix: time.Now().Add(time.Hour).Unix()}
	tmp := filepath.Join(dir, "broker-"+sessionTag("s")+".json.tmp")
	if err := os.Symlink(victim, tmp); err != nil {
		t.Fatal(err)
	}

	if err := WriteBootstrap(spool, bs); err != nil {
		t.Fatalf("WriteBootstrap should still succeed (planted symlink removed, not followed): %v", err)
	}
	// The victim must be untouched.
	if data, _ := os.ReadFile(victim); string(data) != "ORIGINAL" {
		t.Fatalf("victim file was overwritten through the symlink: %q", string(data))
	}
	// The bootstrap must be a regular file with the real content.
	got, err := ReadBootstrap(spool, "s")
	if err != nil || got.DialAddr != "127.0.0.1:1" {
		t.Fatalf("bootstrap not written correctly: %v %+v", err, got)
	}
	fi, _ := os.Lstat(bootstrapPath(spool, "s"))
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("bootstrap path is a symlink")
	}
}

// CTF-4: a symlinked spool subdir is refused (cannot redirect host writes).
func TestWriteBootstrap_RefusesSymlinkedDir(t *testing.T) {
	spool := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(spool, spoolSubdir)); err != nil {
		t.Fatal(err)
	}
	err := WriteBootstrap(spool, Bootstrap{Session: "s", TokenB64: "dG9rZW4="})
	if err == nil {
		t.Fatal("expected refusal to write into a symlinked spool subdir")
	}
}
