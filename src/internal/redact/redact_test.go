package redact

import (
	"regexp"
	"strings"
	"testing"

	"github.com/hsoftai/hsoft-claude-plugins/internal/detect"
)

func newRedactor() *Redactor {
	return New(detect.New())
}

var placeholderRe = regexp.MustCompile(`\[REDACTED_[A-Z_]+_[0-9a-f]{8}\]`)

func TestRedact_ReplacesSecret(t *testing.T) {
	r := newRedactor()
	in := "deploy with AKIAIOSFODNN7EXAMPLE now"
	out, reps := r.Redact(in)

	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret still present: %q", out)
	}
	if !placeholderRe.MatchString(out) {
		t.Fatalf("expected a placeholder in %q", out)
	}
	if len(reps) != 1 || reps[0].Category != detect.CategoryAWSAccessKey {
		t.Fatalf("expected 1 AWS replacement, got %+v", reps)
	}
}

func TestRedact_DeterministicPerValue(t *testing.T) {
	r := newRedactor()
	key := "AKIAIOSFODNN7EXAMPLE"
	in := key + " and again " + key
	out, _ := r.Redact(in)

	ph := placeholderRe.FindAllString(out, -1)
	if len(ph) != 2 {
		t.Fatalf("expected 2 placeholders, got %d in %q", len(ph), out)
	}
	if ph[0] != ph[1] {
		t.Fatalf("same value must map to same placeholder: %q vs %q", ph[0], ph[1])
	}
}

func TestRedact_Idempotent(t *testing.T) {
	r := newRedactor()
	in := "GH_TOKEN=ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz and AKIAIOSFODNN7EXAMPLE"
	once, _ := r.Redact(in)
	twice, reps := r.Redact(once)

	if once != twice {
		t.Fatalf("redaction not idempotent:\n once: %q\ntwice: %q", once, twice)
	}
	if len(reps) != 0 {
		t.Fatalf("second pass should find nothing, got %+v", reps)
	}
}

func TestRedact_LeavesCleanTextUnchanged(t *testing.T) {
	r := newRedactor()
	in := "just a normal sentence about deployments"
	out, reps := r.Redact(in)
	if out != in {
		t.Fatalf("clean text changed: %q -> %q", in, out)
	}
	if len(reps) != 0 {
		t.Fatalf("expected no replacements, got %+v", reps)
	}
}

func TestRedact_MultipleDistinctSecrets(t *testing.T) {
	r := newRedactor()
	in := "aws AKIAIOSFODNN7EXAMPLE gh ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
	out, reps := r.Redact(in)
	if strings.Contains(out, "AKIA") || strings.Contains(out, "ghp_") {
		t.Fatalf("a secret survived: %q", out)
	}
	if len(reps) != 2 {
		t.Fatalf("expected 2 replacements, got %d: %+v", len(reps), reps)
	}
}

func TestRedact_PreservesVaultReferences(t *testing.T) {
	r := newRedactor()
	in := "connect using keeper://AbC123/field/password please"
	out, reps := r.Redact(in)
	if out != in || len(reps) != 0 {
		t.Fatalf("vault reference must be preserved: %q -> %q (%+v)", in, out, reps)
	}
}
