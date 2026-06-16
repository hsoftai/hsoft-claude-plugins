package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestScanRefFiles(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(".env", "DB=op://v/i/password\nPORT=8080\n")           // matches, has ref
	write("config.yaml", "token: keeper://UID/field/password\n") // matches, has ref
	write("settings.json", `{"x":"op://a/b/c"}`)                 // matches, has ref
	write("README.md", "see op://v/i/p")                         // no glob match → skipped
	write("clean.yaml", "port: 8080\n")                          // matches glob, no ref
	write("node_modules/pkg/.env", "K=op://v/i/p")               // skipped dir
	write("sub/app.toml", "secret = \"op://t/u/v\"\n")           // nested, matches

	// binary file with a matching glob name must be skipped
	write("bin.json", "{\"a\":\"op://x/y/z\"\x00}")

	files, truncated := scanRefFiles(root, defaultGlobs())
	if truncated {
		t.Fatalf("unexpected truncation")
	}

	var got []string
	for _, f := range files {
		rel, _ := filepath.Rel(root, f.path)
		got = append(got, rel)
	}
	sort.Strings(got)

	want := []string{".env", "config.yaml", "settings.json", "sub/app.toml"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestMatchesGlob(t *testing.T) {
	g := defaultGlobs()
	for _, name := range []string{".env", ".env.local", "prod.env", "config.yaml", "appsettings.json", "x.toml"} {
		if !matchesGlob(name, g) {
			t.Fatalf("%q should match", name)
		}
	}
	for _, name := range []string{"main.go", "README.md", "image.png", "script.sh"} {
		if matchesGlob(name, g) {
			t.Fatalf("%q should NOT match", name)
		}
	}
}
