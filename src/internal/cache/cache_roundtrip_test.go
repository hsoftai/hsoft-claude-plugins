package cache

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestCacheRoundTrip verifies the per-session in-memory cache works on THIS platform
// (including Windows, where the socket-dir ownership check previously rejected it): with
// the daemon running, a value added is found and redacted when it reappears. This is the
// basis of the redaction guard in the local model (no sandbox-dlp service). The daemon is
// run in-process (a unit test binary has no `cache-daemon` subcommand to spawn).
func TestCacheRoundTrip(t *testing.T) {
	dir, err := os.MkdirTemp("", "sgc-rt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Setenv("SG_CACHE_DIR", dir)

	const sess = "roundtrip-session"
	go func() { _ = RunDaemon(sess) }()

	// Wait for the daemon to be listening (proves net.Listen("unix") works here).
	up := false
	for i := 0; i < 60; i++ {
		if _, ok := roundtrip(sess, request{Op: "ping"}, false); ok {
			up = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !up {
		t.Fatal("cache daemon never came up (unix socket unavailable on this platform?)")
	}
	defer New().Shutdown(sess)

	c := New()
	c.Add(sess, []string{"SUPER-SECRET-VALUE-123"})

	found, red, ok := c.Scan(sess, "prefix SUPER-SECRET-VALUE-123 suffix")
	if !ok {
		t.Fatal("cache scan unavailable")
	}
	if !found || strings.Contains(red, "SUPER-SECRET-VALUE-123") || !strings.Contains(red, "REDACTED") {
		t.Fatalf("value not redacted: found=%v red=%q", found, red)
	}

	if found2, red2, ok2 := c.Scan(sess, "nothing secret here"); !ok2 || found2 || red2 != "nothing secret here" {
		t.Fatalf("clean scan wrong: found=%v red=%q ok=%v", found2, red2, ok2)
	}
}
