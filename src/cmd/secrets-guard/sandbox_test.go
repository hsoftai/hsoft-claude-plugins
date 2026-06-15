package main

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

func TestParseSandboxArgs(t *testing.T) {
	if got := parseSandboxArgs([]string{"--", "sh", "-c", "echo hi"}); strings.Join(got, " ") != "sh -c echo hi" {
		t.Fatalf("got %v", got)
	}
	if got := parseSandboxArgs([]string{"sh", "-c", "x"}); strings.Join(got, " ") != "sh -c x" {
		t.Fatalf("got %v", got)
	}
	if got := parseSandboxArgs(nil); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestStripSandboxEnv(t *testing.T) {
	in := map[string]string{
		"PATH": "/bin", "SG_CW_HOSTPUB": "x", "SG_CW_EXECID": "e",
		"SG_IN_NS": "1", "SG_SANDBOX_ACTIVE": "1", "FOO": "bar",
	}
	out := stripSandboxEnv(in)
	for _, k := range []string{"SG_CW_HOSTPUB", "SG_CW_EXECID", "SG_IN_NS", "SG_SANDBOX_ACTIVE"} {
		if _, ok := out[k]; ok {
			t.Fatalf("%s must be stripped", k)
		}
	}
	if out["PATH"] != "/bin" || out["FOO"] != "bar" {
		t.Fatalf("non-control vars must survive: %v", out)
	}
}

func TestEnvReferenceSet(t *testing.T) {
	t.Setenv("SG_TEST_A", "op://v/i/password")
	t.Setenv("SG_TEST_B", "plain")
	t.Setenv("SG_TEST_C", "keeper://UID/field/password and op://x/y/z")
	got := envReferenceSet()
	sort.Strings(got)
	// must include the three refs (other env vars may add more, so check membership)
	want := map[string]bool{
		"op://v/i/password":           true,
		"keeper://UID/field/password": true,
		"op://x/y/z":                  true,
	}
	for w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing ref %q in %v", w, got)
		}
	}
}

// renderEnvValue is the env-substitution used by the sandbox; verify it renders
// every known reference and leaves unknown ones and plain text intact.
func renderEnvValue(v string, values map[string]string) string {
	for _, r := range vault.FindReferences(v) {
		if val, ok := values[r]; ok {
			v = strings.ReplaceAll(v, r, val)
		}
	}
	return v
}

func TestRenderEnvValue(t *testing.T) {
	values := map[string]string{"op://v/i/p": "S3CR3T", "op://a/b/c": "OTHER"}
	cases := map[string]string{
		"op://v/i/p":                "S3CR3T",
		"prefix op://a/b/c suffix":  "prefix OTHER suffix", // space terminates the ref
		"\"op://a/b/c\"":            "\"OTHER\"",           // quotes terminate the ref
		"op://v/i/p and op://a/b/c": "S3CR3T and OTHER",
		"op://unknown/x/y":          "op://unknown/x/y", // unresolved → literal
		"no references here":        "no references here",
	}
	for in, want := range cases {
		if got := renderEnvValue(in, values); got != want {
			t.Fatalf("renderEnvValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSandboxArgs_NoEnvLeakHelper(t *testing.T) {
	// regression: stripSandboxEnv operates on a real os.Environ-shaped map
	env := environMap()
	env["SG_SANDBOX_ACTIVE"] = "1"
	out := stripSandboxEnv(env)
	if _, ok := out["SG_SANDBOX_ACTIVE"]; ok {
		t.Fatal("control var leaked")
	}
	_ = os.Environ
}

func TestRenderRefs_Escape(t *testing.T) {
	values := map[string]string{"op://v/i/p": "SECRET", "keeper://U/f/p": "KSECRET"}
	cases := map[string]string{
		"op://v/i/p":                       "SECRET",                     // resolved
		`\op://v/i/p`:                      "op://v/i/p",                 // escaped: literal, backslash stripped
		"a op://v/i/p b":                   "a SECRET b",                 // in context
		`a \op://v/i/p b`:                  "a op://v/i/p b",             // escaped in context
		"keeper://U/f/p":                   "KSECRET",                    // keeper scheme
		"op://unknown/x/y":                 "op://unknown/x/y",           // unresolved → literal
		"both op://v/i/p and \\op://v/i/p": "both SECRET and op://v/i/p", // mixed
	}
	for in, want := range cases {
		if got := renderRefs(in, values); got != want {
			t.Fatalf("renderRefs(%q) = %q, want %q", in, got, want)
		}
	}
}

// CTF-7 regression: the leak-backstop dirs handed to the unshare child are computed
// in the OUTER process (host uid), and any operator override is honored verbatim, so
// the namespace child (where Getuid()==mapped-0) registers rendered values where the
// host hooks look — not under a uid-0 path the host never scans.
func TestHostBackstopDirs(t *testing.T) {
	t.Setenv("SG_CACHE_DIR", "/host/cache")
	t.Setenv("SG_PATHS_DIR", "/host/paths")
	if got := hostCacheDir(); got != "/host/cache" {
		t.Fatalf("hostCacheDir ignored override: %q", got)
	}
	if got := hostPathsDir(); got != "/host/paths" {
		t.Fatalf("hostPathsDir ignored override: %q", got)
	}

	// Without overrides the dirs are uid-keyed and stable across calls (so the value
	// the outer process pins matches what the host hook independently computes).
	os.Unsetenv("SG_CACHE_DIR")
	os.Unsetenv("SG_PATHS_DIR")
	if a, b := hostCacheDir(), hostCacheDir(); a != b || !strings.Contains(a, "secrets-guard-sock-") {
		t.Fatalf("hostCacheDir not uid-stable: %q vs %q", a, b)
	}
	if a, b := hostPathsDir(), hostPathsDir(); a != b || !strings.Contains(a, "secrets-guard-paths-") {
		t.Fatalf("hostPathsDir not uid-stable: %q vs %q", a, b)
	}
	// SG_PATHS_DIR is a control var and must not leak into the rendered child env.
	env := map[string]string{"SG_PATHS_DIR": "/host/paths", "FOO": "bar"}
	if out := stripSandboxEnv(env); out["SG_PATHS_DIR"] != "" || out["FOO"] != "bar" {
		t.Fatalf("SG_PATHS_DIR must be stripped from child env: %v", out)
	}
}

func TestUnescapedRefs(t *testing.T) {
	got := unescapedRefs(`op://a/b/c and \op://escaped/x/y and keeper://U/f/p`)
	want := map[string]bool{"op://a/b/c": true, "keeper://U/f/p": true}
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 unescaped refs", got)
	}
	for _, r := range got {
		if !want[r] {
			t.Fatalf("unexpected (or escaped) ref %q in %v", r, got)
		}
	}
}
