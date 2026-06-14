// Package audit appends tamper-evident, value-free decision records to a local
// log file. It records what category of secret was acted on and how, never the
// secret value itself.
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Record is a single audit entry. It must never contain a secret value.
type Record struct {
	Time       string   `json:"time"`
	SessionID  string   `json:"session_id,omitempty"`
	Event      string   `json:"event"`
	Action     string   `json:"action"`
	Categories []string `json:"categories,omitempty"`
	Count      int      `json:"count"`
}

// Logger appends records to a file. A Logger with an empty path is a no-op.
type Logger struct {
	path string
	mu   sync.Mutex
	now  func() time.Time
}

// New returns a Logger writing to path (no-op if path is "").
func New(path string) *Logger {
	return &Logger{path: path, now: time.Now}
}

// Log appends rec as a JSON line. Errors are swallowed: auditing must never
// break the security hook itself.
func (l *Logger) Log(rec Record) {
	if l.path == "" {
		return
	}
	if rec.Time == "" {
		rec.Time = l.now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}
