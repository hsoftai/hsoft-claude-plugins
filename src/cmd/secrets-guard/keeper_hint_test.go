package main

import (
	"strings"
	"testing"
)

func TestKeeperErrorHint(t *testing.T) {
	cases := []struct{ msg, want string }{
		{"ksm had a problem: Error: access_denied, message=This client is locked to a different ip address", "IP-lock"},
		{"access_denied, message=Unable to validate Keeper application access", "Shared Folder"},
		{"The Keeper SDK client has not been loaded. The INI config might not be set.", "one-time token"},
		{"some unrelated error", ""},
	}
	for _, c := range cases {
		got := keeperErrorHint(c.msg)
		if c.want == "" {
			if got != "" {
				t.Errorf("keeperErrorHint(%q) = %q, want empty", c.msg, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("keeperErrorHint(%q) = %q, want to contain %q", c.msg, got, c.want)
		}
	}
}
