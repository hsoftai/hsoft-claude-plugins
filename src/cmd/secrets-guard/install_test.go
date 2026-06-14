package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fileChanged drives the SessionStart self-install idempotency: it must recopy
// only when the destination is missing, a different size, or older than source.
func TestFileChanged(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	if err := os.WriteFile(src, []byte("hello-world"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Destination missing → must copy.
	if !fileChanged(src, dst) {
		t.Fatal("missing destination should report changed")
	}

	// Identical content, dst at least as new as src → no copy.
	if err := os.WriteFile(dst, []byte("hello-world"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_ = os.Chtimes(src, now, now)
	_ = os.Chtimes(dst, now, now)
	if fileChanged(src, dst) {
		t.Fatal("same size and not-older destination should report unchanged")
	}

	// Different size → must copy.
	if err := os.WriteFile(dst, []byte("short"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(dst, now, now)
	if !fileChanged(src, dst) {
		t.Fatal("different size should report changed")
	}

	// Source newer than destination → must copy.
	if err := os.WriteFile(dst, []byte("hello-world"), 0o755); err != nil {
		t.Fatal(err)
	}
	older := now.Add(-time.Hour)
	_ = os.Chtimes(dst, older, older)
	_ = os.Chtimes(src, now, now)
	if !fileChanged(src, dst) {
		t.Fatal("source newer than destination should report changed")
	}
}
