package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hsoftai/hsoft-claude-plugins/internal/cache"
	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
)

// This file orchestrates the per-user, NO-ADMIN install/uninstall of secrets-guard in the
// local model (no sandbox-dlp service, no WinFsp). Both a CLEAN environment and a DIRTY one
// (some components already present, or a leftover from the old WinFsp/service model)
// converge to the same working state: the CLI on PATH, legacy components removed, and the
// redaction guard reading the user's local vault.

// removeIfExists deletes a file or directory if present; returns true if it existed.
func removeIfExists(path string) bool {
	if path == "" {
		return false
	}
	if _, err := os.Stat(path); err != nil {
		return false
	}
	return os.RemoveAll(path) == nil
}

// cliInstalled reports whether the secrets-guard CLI is already in the per-user bin dir.
func cliInstalled() bool {
	_, err := os.Stat(filepath.Join(installTargetDir(), installBinName()))
	return err == nil
}

// vaultStatusBrief returns the active provider, whether it resolves, and a value-free
// detail string.
func vaultStatusBrief(cfg config.Config) (provider string, ready bool, detail string) {
	prov, n, err := vaultValueCount(cfg)
	if err != nil {
		if prov == "" {
			return "none", false, err.Error()
		}
		return prov, false, err.Error()
	}
	return prov, true, fmt.Sprintf("%d secret values", n)
}

// runInstall is `secrets-guard install [--dir DIR]`: idempotent, descriptive, no admin. It
// installs the CLI on PATH, cleans up any legacy WinFsp/service footprint (dirty install),
// reports the vault state and warms the guard cache.
func runInstall() {
	dir := ""
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--dir" && i+1 < len(args) {
			dir = args[i+1]
			i++
		}
	}
	cfg := config.Load(os.Getenv)
	fmt.Println("secrets-guard install — local model (per-user, no admin, no service)")
	fmt.Println()

	hadCLI := cliInstalled()
	dst, err := selfInstall(dir, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "  ✗ CLI install failed:", err)
		os.Exit(1)
	}
	if hadCLI {
		fmt.Printf("  • CLI: already present — refreshed at %s\n", dst)
	} else {
		fmt.Printf("  • CLI: installed at %s\n", dst)
	}

	stale := staleComponents()
	if len(stale) == 0 {
		fmt.Println("  • Legacy components: none")
	} else {
		fmt.Printf("  • Legacy components present: %v\n", stale)
		if removed := removeStale(); len(removed) > 0 {
			fmt.Printf("    → cleaned up: %v\n", removed)
		}
	}

	prov, ready, detail := vaultStatusBrief(cfg)
	if ready {
		fmt.Printf("  • Vault: %s ready (%s) — full redaction guard active\n", prov, detail)
		if sess := os.Getenv("SG_SESSION"); sess != "" {
			if vals, e := allVaultValues(cfg); e == nil && len(vals) > 0 {
				cache.New().Add(sess, vals)
			}
		}
	} else {
		fmt.Printf("  • Vault: not initialized yet — %s\n", detail)
		fmt.Println("    initialize it (e.g. `ksm profile init <one-time-token>`); until then the guard uses the pattern detector and never blocks use.")
	}

	fmt.Println()
	switch {
	case !hadCLI && len(stale) == 0:
		fmt.Println("Clean install complete.")
	case len(stale) > 0:
		fmt.Println("Setup complete — cleaned up legacy components and configured the rest.")
	default:
		fmt.Println("Already set up — refreshed the CLI; nothing else to do.")
	}
	printPathHint(filepath.Dir(dst))
}

// runUninstall is `secrets-guard uninstall`: removes the entire secrets-guard footprint
// (the CLI, its PATH entry, any legacy WinFsp/service + workaround components, and session
// caches), leaving the user's own vault profile intact. No admin required.
func runUninstall() {
	fmt.Println("secrets-guard uninstall — removing the per-user footprint")
	fmt.Println()
	removed := uninstallEnv()
	if len(removed) == 0 {
		fmt.Println("  Nothing found to remove (already clean).")
	} else {
		for _, r := range removed {
			fmt.Println("  • removed:", r)
		}
	}
	fmt.Println()
	fmt.Println("Left intact: your ksm/op vault profile (your own vault access is untouched).")
	fmt.Println("To finish: disable/remove the plugin in Claude Code (/plugin), and remove the")
	fmt.Println("secrets-guard entry from managed-settings.json if your organization set one.")
}
