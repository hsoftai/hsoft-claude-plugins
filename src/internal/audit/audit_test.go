package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogger_WritesRecordWithoutValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := New(path)

	l.Log(Record{
		SessionID:  "sess-1",
		Event:      "PostToolUse",
		Action:     "redact",
		Categories: []string{"AWS_ACCESS_KEY"},
		Count:      1,
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := string(data)
	if !strings.Contains(line, "PostToolUse") || !strings.Contains(line, "redact") || !strings.Contains(line, "AWS_ACCESS_KEY") {
		t.Fatalf("record missing fields: %q", line)
	}
	if !strings.Contains(line, "\"count\":1") {
		t.Fatalf("count not recorded: %q", line)
	}
}

func TestLogger_EmptyPathIsNoop(t *testing.T) {
	l := New("")
	// Must not panic or error.
	l.Log(Record{Event: "UserPromptSubmit", Action: "block"})
}

func TestLogger_AppendsLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := New(path)
	l.Log(Record{Event: "PreToolUse", Action: "inject", Count: 1})
	l.Log(Record{Event: "PreToolUse", Action: "deny", Count: 1})

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
}
