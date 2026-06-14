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
