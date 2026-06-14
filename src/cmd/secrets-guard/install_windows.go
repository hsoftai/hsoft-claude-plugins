//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// installTargetDir is %LOCALAPPDATA%\secrets-guard\bin — a per-user location that
// needs no administrator rights.
func installTargetDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, "AppData", "Local")
	}
	return filepath.Join(base, "secrets-guard", "bin")
}

func installBinName() string { return "secrets-guard.exe" }

// winPathRe extracts the value of the user's Path from `reg query` output, e.g.
//
//	Path    REG_EXPAND_SZ    C:\Users\me\AppData\Local\Microsoft\WindowsApps;...
//
// The value may itself contain spaces (C:\Program Files\…), so we capture
// everything after the REG_*SZ type token rather than splitting on whitespace.
var winPathRe = regexp.MustCompile(`(?i)\bPath\b\s+REG_\w+\s+(.*)`)

// ensureOnUserPath adds dir to the user's PATH in the registry (HKCU\Environment)
// — no administrator rights. New terminals (cmd / PowerShell) pick it up. We go
// through reg.exe (always present) to avoid any external dependency. The system
// PATH is untouched; Windows merges system + user PATH for each new shell.
func ensureOnUserPath(dir string, quiet bool) error {
	cur := userPath()
	for _, p := range strings.Split(cur, ";") {
		if strings.EqualFold(strings.TrimRight(strings.TrimSpace(p), `\`), strings.TrimRight(dir, `\`)) {
			return nil // already present
		}
	}
	newVal := dir
	if strings.TrimSpace(cur) != "" {
		newVal = strings.TrimRight(cur, ";") + ";" + dir
	}
	cmd := exec.Command("reg", "add", `HKCU\Environment`, "/v", "Path",
		"/t", "REG_EXPAND_SZ", "/d", newVal, "/f")
	return cmd.Run()
}

// userPath reads the current per-user PATH from the registry. Returns "" if the
// user has no Path value yet (only the system PATH applies) — that is fine, we
// then create it with just our directory.
func userPath() string {
	out, err := exec.Command("reg", "query", `HKCU\Environment`, "/v", "Path").Output()
	if err != nil {
		return ""
	}
	if m := winPathRe.FindStringSubmatch(string(out)); m != nil {
		return strings.TrimRight(m[1], "\r\n ")
	}
	return ""
}

func printPathHint(dir string) {
	fmt.Printf("✓ Added %s to your user PATH. Open a NEW terminal (cmd or PowerShell), then run: secrets-guard version\n", dir)
}
