// Package redact replaces detected secrets with deterministic, value-stable
// placeholders. The same secret value always maps to the same placeholder
// (derived from a hash of the value), which keeps redaction idempotent and
// preserves Claude's prompt-cache hit rate across turns.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/hsoftai/hsoft-claude-plugins/internal/detect"
)

// Replacement records a single redaction for auditing. It never carries the
// original secret value.
type Replacement struct {
	Category    detect.Category
	Placeholder string
}

// Redactor wraps a detection engine and rewrites secrets out of text.
type Redactor struct {
	eng *detect.Engine
}

// New returns a Redactor backed by eng.
func New(eng *detect.Engine) *Redactor {
	return &Redactor{eng: eng}
}

// Redact returns text with every detected secret replaced by a deterministic
// placeholder, along with the list of replacements performed.
func (r *Redactor) Redact(text string) (string, []Replacement) {
	findings := r.eng.Scan(text)
	if len(findings) == 0 {
		return text, nil
	}

	// Replace from the end so earlier offsets stay valid.
	var reps []Replacement
	out := text
	for i := len(findings) - 1; i >= 0; i-- {
		f := findings[i]
		ph := placeholder(f.Category, f.Value)
		out = out[:f.Start] + ph + out[f.End:]
		reps = append(reps, Replacement{Category: f.Category, Placeholder: ph})
	}

	// Reverse reps so they read in document order.
	for i, j := 0, len(reps)-1; i < j; i, j = i+1, j-1 {
		reps[i], reps[j] = reps[j], reps[i]
	}
	return out, reps
}

// placeholder builds a stable token of the form [REDACTED_<CATEGORY>_<hash8>].
func placeholder(cat detect.Category, value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("[REDACTED_%s_%s]", cat, hex.EncodeToString(sum[:])[:8])
}
