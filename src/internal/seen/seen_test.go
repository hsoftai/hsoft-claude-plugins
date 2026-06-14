package seen

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestRecordLoadClearPaths(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	s := "sess-1"
	RecordPaths(s, []string{"op://Private/db/password", "op://Private/db/password", "keeper://uid/field/password"})
	got := LoadPaths(s)
	if len(got) != 2 {
		t.Fatalf("expected 2 deduped paths, got %v", got)
	}
	Clear(s)
	if len(LoadPaths(s)) != 0 {
		t.Fatal("Clear should remove the ledger")
	}
}

func TestContainsAndRedact_Raw(t *testing.T) {
	v := []string{"arb34va34va34"}
	if !Contains("the file says arb34va34va34 ok", v) {
		t.Fatal("raw value not detected")
	}
	out, n := Redact("x=arb34va34va34", v)
	if n != 1 || strings.Contains(out, "arb34va34va34") {
		t.Fatalf("raw not redacted: %q n=%d", out, n)
	}
}

func TestContainsAndRedact_Encodings(t *testing.T) {
	secret := "S3cr3tP4ssw0rd"
	v := []string{secret}

	cases := map[string]string{
		"base64":          base64.StdEncoding.EncodeToString([]byte(secret)),
		"base64url-nopad": base64.RawURLEncoding.EncodeToString([]byte(secret)),
		"hex":             hex.EncodeToString([]byte(secret)),
		"HEX":             strings.ToUpper(hex.EncodeToString([]byte(secret))),
	}
	for name, enc := range cases {
		text := "leaked payload: " + enc + " done"
		if !Contains(text, v) {
			t.Errorf("%s encoding not detected: %s", name, enc)
		}
		out, n := Redact(text, v)
		if n == 0 || strings.Contains(out, enc) {
			t.Errorf("%s encoding not redacted: out=%q", name, out)
		}
	}
}

func TestContains_ShortValueIgnored(t *testing.T) {
	if Contains("abc here", []string{"abc"}) {
		t.Fatal("values shorter than minLen must be ignored to avoid noise")
	}
}
