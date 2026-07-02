package main

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.8.4", "0.8.2", 1},
		{"0.8.2", "0.8.4", -1},
		{"0.8.4", "0.8.4", 0},
		{"0.9.0", "0.8.9", 1},
		{"1.0.0", "0.9.9", 1},
		{"0.8.10", "0.8.9", 1}, // numeric, not lexical
		{"v0.8.4", "0.8.4", 0}, // leading v tolerated
		{"0.8.4-rc1", "0.8.4", 0}, // pre-release suffix ignored on that part
		{"dev", "0.8.4", 1},    // dev sorts highest (never auto-downgrade a local build)
		{"0.8.4", "dev", -1},
		{"", "0.8.4", 1}, // unknown sorts highest
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestPlatformAssetName(t *testing.T) {
	n := platformAssetName()
	if n == "" {
		t.Fatal("empty asset name")
	}
	// Must start with the shared prefix and be OS/arch specific.
	if len(n) < len("secrets-guard-") || n[:len("secrets-guard-")] != "secrets-guard-" {
		t.Errorf("asset name %q missing prefix", n)
	}
}
