package seen

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"testing"
)

// skipOnWindows marks tests whose subject is the Unix ledger-directory model — the
// TMPDIR location, the per-uid keying, and the 0700/owner ownership check. Windows uses a
// different per-user location and ACL model, so these do not apply there.
func skipOnWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ledger-dir semantics (TMPDIR, per-uid, 0700/owner) do not apply on Windows")
	}
}

func TestRecordLoadClearPaths(t *testing.T) {
	skipOnWindows(t)
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

// CTF-3 regression: the ledger lives in a PER-UID dir (not a fixed shared
// /tmp/secrets-guard-paths), and a hijacked / loose-permissioned dir is refused
// (fail-closed) rather than adopted — so a co-resident user cannot silently
// disable the resolved-value leak backstop by pre-planting the dir.
func TestLedgerDirIsPerUidAndOwnershipChecked(t *testing.T) {
	skipOnWindows(t)
	base := t.TempDir()
	t.Setenv("TMPDIR", base)

	// Path() must land under a uid-keyed directory, never the bare shared name.
	p := Path("sess-x")
	if p == "" {
		t.Fatal("Path empty for a freshly-created, owned dir")
	}
	if strings.Contains(p, "secrets-guard-paths/") && !strings.Contains(p, "secrets-guard-paths-") {
		t.Fatalf("ledger not in a per-uid dir: %s", p)
	}

	// A loosely-permissioned (0777) dir must be refused: Path returns "" and
	// RecordPaths fails closed instead of trusting it.
	t.Setenv("TMPDIR", t.TempDir())
	if d := dir(); d != "" {
		if err := os.Chmod(d, 0o777); err == nil {
			if got := Path("sess-y"); got != "" {
				t.Fatalf("Path should refuse a 0777 ledger dir, got %q", got)
			}
			RecordPaths("sess-y", []string{"op://Private/db/password"})
			if v := LoadPaths("sess-y"); len(v) != 0 {
				t.Fatalf("RecordPaths must fail closed on an unsafe dir, got %v", v)
			}
		}
	}
}

// CTF-7 regression: when the sandbox re-execs under `unshare --map-root-user`,
// os.Getuid() inside the namespace is the mapped 0 — NOT the host uid — so the
// default per-uid ledger dir (secrets-guard-paths-0) is a path the host hooks,
// which read secrets-guard-paths-<realuid>, never consult. The rendered value
// would be fetched but never registered for the leak-block. SG_PATHS_DIR lets the
// outer (pre-unshare) process pin the host's ledger dir so the namespace child
// records into the SAME directory the host reads.
func TestPathsDirOverride(t *testing.T) {
	skipOnWindows(t)
	// Simulate: host hooks read uid-based dir; the namespace child gets SG_PATHS_DIR.
	hostDir := t.TempDir()
	// The ownership check requires an exclusively-owned 0700 dir (t.TempDir may be 0755).
	if err := os.Chmod(hostDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SG_PATHS_DIR", hostDir)

	RecordPaths("sess-ns", []string{"op://Private/db/password"})

	got := LoadPaths("sess-ns")
	if len(got) != 1 || got[0] != "op://Private/db/password" {
		t.Fatalf("ledger not written to the pinned host dir: %v", got)
	}
	// The ledger file must physically live in the pinned directory, not a uid-keyed one.
	if d := dir(); d != hostDir {
		t.Fatalf("dir() ignored SG_PATHS_DIR: got %q want %q", d, hostDir)
	}
	if entries, _ := os.ReadDir(hostDir); len(entries) == 0 {
		t.Fatal("expected the ledger file to exist under the pinned dir")
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

// CTF-4 (round 4) regression: the single-line base64 variant does NOT appear as a
// substring once a tool wraps the output — `base64`/`openssl base64`, MIME and PEM
// all break the stream into fixed-width lines. `echo -n "$SECRET" | base64` (the most
// obvious exfil one-liner) and reading a wrapped file would otherwise slip past the
// substring leak-block. The wrapped forms must be detected and redacted too.
func TestContainsAndRedact_WrappedBase64(t *testing.T) {
	// Long enough that the base64 form exceeds one wrap line (>76 cols).
	secret := strings.Repeat("S3cr3tValue-", 6)
	v := []string{secret}
	std := base64.StdEncoding.EncodeToString([]byte(secret))

	wrap := func(width int, sep string) string {
		var b strings.Builder
		for i := 0; i < len(std); i += width {
			if i > 0 {
				b.WriteString(sep)
			}
			end := i + width
			if end > len(std) {
				end = len(std)
			}
			b.WriteString(std[i:end])
		}
		return b.String()
	}

	cases := map[string]string{
		"base64-76-lf":   wrap(76, "\n"),   // GNU coreutils default
		"base64-64-lf":   wrap(64, "\n"),   // openssl base64 / PEM / MIME
		"base64-64-crlf": wrap(64, "\r\n"), // MIME (CRLF)
	}
	for name, enc := range cases {
		if strings.Contains(enc, std) {
			t.Fatalf("%s: test setup wrong — wrapped form still contains the single-line variant", name)
		}
		text := "exfil:\n" + enc + "\ndone"
		if !Contains(text, v) {
			t.Errorf("%s: wrapped base64 not detected", name)
		}
		out, n := Redact(text, v)
		if n == 0 || strings.Contains(out, std[:24]) {
			t.Errorf("%s: wrapped base64 not redacted: n=%d out=%q", name, n, out)
		}
	}
}

func TestContains_ShortValueIgnored(t *testing.T) {
	if Contains("abc here", []string{"abc"}) {
		t.Fatal("values shorter than minLen must be ignored to avoid noise")
	}
}

// CTF-5 regression: cheap reversible transforms (reverse, case-fold) an
// exfiltrator might use to dodge substring DLP are detected/redacted.
func TestContainsAndRedact_CheapTransforms(t *testing.T) {
	secret := "S3cr3tP4ssw0rd"
	v := []string{secret}

	rev := func(s string) string {
		b := []byte(s)
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return string(b)
	}
	for name, t1 := range map[string]string{
		"reversed":  rev(secret),
		"lowercase": strings.ToLower(secret),
		"uppercase": strings.ToUpper(secret),
	} {
		text := "exfil: " + t1 + " end"
		if !Contains(text, v) {
			t.Errorf("%s transform not detected: %s", name, t1)
		}
		if out, n := Redact(text, v); n == 0 || strings.Contains(out, t1) {
			t.Errorf("%s transform not redacted: %q", name, out)
		}
	}

	// CTF-4 (minLen): a 4-char secret is now tracked (no longer ignored).
	if !Contains("pin is 4tz9 ok", []string{"4tz9"}) {
		t.Fatal("4-char secret should be tracked after minLen=4")
	}
}
