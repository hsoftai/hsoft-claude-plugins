//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// installTargetDir is ~/.local/bin — on the PATH of most modern Linux/macOS
// shells, and writable without administrator rights.
func installTargetDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin")
}

func installBinName() string { return "secrets-guard" }

// ensureOnUserPath makes sure dir is on the user's PATH. On most systems
// ~/.local/bin already is; if not, append an idempotent export line to the user's
// shell rc so new terminals pick it up. Never errors in a way that should break a
// session — a missing rc just gets created.
func ensureOnUserPath(dir string, quiet bool) error {
	if onPath(dir) {
		return nil
	}
	rc := shellRCPath()
	if data, err := os.ReadFile(rc); err == nil && strings.Contains(string(data), dir) {
		return nil // our line (or an equivalent) is already present
	}
	f, err := os.OpenFile(rc, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "\n# Added by secrets-guard install\nexport PATH=\"%s:$PATH\"\n", dir)
	return err
}

// shellRCPath picks the rc file for the user's login shell.
func shellRCPath() string {
	home, _ := os.UserHomeDir()
	sh := os.Getenv("SHELL")
	switch {
	case strings.Contains(sh, "zsh"):
		return filepath.Join(home, ".zshrc")
	case strings.Contains(sh, "bash"):
		return filepath.Join(home, ".bashrc")
	default:
		return filepath.Join(home, ".profile")
	}
}

func printPathHint(dir string) {
	if onPath(dir) {
		fmt.Println("✓ It's already on your PATH — open a new shell and run: secrets-guard version")
		return
	}
	fmt.Printf("✓ Added %s to your PATH (%s). Open a new terminal, then: secrets-guard version\n",
		dir, shellRCPath())
}
