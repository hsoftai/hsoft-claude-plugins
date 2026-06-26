package main

import (
	"os"
	"testing"
	"time"

	"github.com/hsoftai/hsoft-claude-plugins/internal/cache"
	"github.com/hsoftai/hsoft-claude-plugins/internal/detect"
	"github.com/hsoftai/hsoft-claude-plugins/internal/hook"
	"github.com/hsoftai/hsoft-claude-plugins/internal/redact"
	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// nothingRunner reports no vault CLI available, so vault.Select yields a no-op resolver
// (the redaction path under test never resolves — it matches against the cache).
type nothingRunner struct{}

func (nothingRunner) Look(string) bool                { return false }
func (nothingRunner) Run(string, ...string) (string, error) { return "", nil }

// TestLocalGuardRedactsFileReadValue exercises the EXACT local-model redaction path that
// catches a vault value in a file the model reads: the per-session cache holds the value
// (as the SessionStart preload loads it), and PostToolUse(Read) must block the output. If
// this passes, a file-read leaking a value can only mean the cache was not populated (the
// preload did not load the vault).
func TestLocalGuardRedactsFileReadValue(t *testing.T) {
	dir, err := os.MkdirTemp("", "sgc-guard-it")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Setenv("SG_CACHE_DIR", dir)

	const sess = "guard-it"
	go func() { _ = cache.RunDaemon(sess) }()
	// Wait for the daemon (proves cross-call cache works on this platform).
	up := false
	for i := 0; i < 60; i++ {
		if found, _, ok := cache.New().Scan(sess, "x"); ok || found {
			up = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !up {
		t.Fatal("cache daemon never came up")
	}
	defer cache.New().Shutdown(sess)

	const secret = "S3cretPassw0rd-from-the-vault"
	cache.New().Add(sess, []string{secret})

	eng := detect.New()
	resolver, _ := vault.Select("keeper", nothingRunner{}, "")
	h := hook.NewHandler(hook.Config{ToolOutputMode: "redact"}, eng, redact.New(eng), resolver, cache.New(), "")

	out := h.Handle(hook.Input{
		HookEventName: "PostToolUse",
		ToolName:      "Read",
		ToolResponse:  []byte(`{"content":"# notes\nDB_PASSWORD=` + secret + `\nother stuff"}`),
		SessionID:     sess,
	})
	if out.Decision != "block" {
		t.Fatalf("a file read containing a cached vault value must be BLOCKED, got %+v", out)
	}

	// Sanity: a file with no vault value is not blocked.
	clean := h.Handle(hook.Input{
		HookEventName: "PostToolUse",
		ToolName:      "Read",
		ToolResponse:  []byte(`{"content":"# notes\nnothing secret here"}`),
		SessionID:     sess,
	})
	if clean.Decision == "block" {
		t.Fatalf("a clean file read must not be blocked, got %+v", clean)
	}
}
