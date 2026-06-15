package cache

import (
	"encoding/base64"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// shortCacheDir sets SG_CACHE_DIR to a short path (unix sockets are length-capped).
func shortCacheDir(t *testing.T) {
	d, err := os.MkdirTemp("/tmp", "sgc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	t.Setenv("SG_CACHE_DIR", d)
}

func waitSocket(session string) bool {
	for i := 0; i < 60; i++ {
		if c, err := net.DialTimeout("unix", sockPath(session), 50*time.Millisecond); err == nil {
			c.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestDaemonRoundtrip(t *testing.T) {
	shortCacheDir(t)
	session := "test-session"
	go func() { _ = RunDaemon(session) }()
	if !waitSocket(session) {
		t.Fatal("daemon socket never came up")
	}
	c := New()

	c.Add(session, []string{"SUPERSECRETVALUE"})

	found, red, ok := c.Scan(session, "the value is SUPERSECRETVALUE here")
	if !ok || !found || strings.Contains(red, "SUPERSECRETVALUE") {
		t.Fatalf("scan: ok=%v found=%v red=%q", ok, found, red)
	}

	// cached value must also be caught/redacted in base64
	b64 := base64.StdEncoding.EncodeToString([]byte("SUPERSECRETVALUE"))
	if _, red2, _ := c.Scan(session, "payload "+b64+" end"); strings.Contains(red2, b64) {
		t.Fatalf("base64 of cached value not redacted: %q", red2)
	}

	// clean text untouched
	if f, _, _ := c.Scan(session, "nothing sensitive here"); f {
		t.Fatal("clean text should not match")
	}

	c.Shutdown(session)
}

func TestScan_NoDaemonReturnsNotOK(t *testing.T) {
	shortCacheDir(t)
	found, _, ok := New().Scan("missing-session", "anything")
	if ok || found {
		t.Fatalf("scan with no daemon must return ok=false: ok=%v found=%v", ok, found)
	}
}

// CTF-9 regression: the cache socket directory must be exclusively OUR own 0700 dir.
// On sticky /tmp a co-resident user could pre-create secrets-guard-sock-<victim-uid>
// (or it could be left loose-permissioned) and squat an impostor daemon that answers
// `scan` as clean — silently disabling the resolved-value leak backstop. The cache
// must refuse a non-exclusively-owned dir and FAIL CLOSED: sockPath()=="" , the
// daemon refuses to bind, and the client reports the cache unavailable (so the hook
// falls back to the on-disk reference ledger instead of trusting a foreign process).
func TestSocketDirOwnershipFailsClosed(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: 0o077 perm bits do not exclude the owner check meaningfully")
	}
	d, err := os.MkdirTemp("/tmp", "sgc-hijack")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	// Loosely-permissioned (group/other-accessible) dir: not exclusively ours.
	if err := os.Chmod(d, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SG_CACHE_DIR", d)

	if p := sockPath("sess-hijack"); p != "" {
		t.Fatalf("sockPath must be empty for a non-exclusively-owned dir, got %q", p)
	}

	// The daemon must refuse to bind under such a dir.
	if err := RunDaemon("sess-hijack"); err == nil {
		t.Fatal("RunDaemon must refuse a non-exclusively-owned socket dir")
	}

	// The client must report the cache as unavailable (ok=false) so the caller falls
	// back to the on-disk ledger rather than trusting an impostor's "clean" answer.
	if found, _, ok := New().Scan("sess-hijack", "value SUPERSECRETVALUE here"); ok || found {
		t.Fatalf("scan over an unsafe socket dir must fail closed: ok=%v found=%v", ok, found)
	}
	// Add must be a no-op (must not spawn a daemon into the poisoned dir).
	New().Add("sess-hijack", []string{"SUPERSECRETVALUE"})

	// And once the dir is tightened to 0700 (exclusively ours), the cache works again.
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if p := sockPath("sess-hijack"); p == "" {
		t.Fatal("sockPath must be non-empty once the dir is a proper 0700 owned dir")
	}
}
