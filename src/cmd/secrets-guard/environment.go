package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hsoftai/hsoft-claude-plugins/internal/cache"
	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// This file orchestrates the per-user, NO-ADMIN install/uninstall of secrets-guard in the
// local model (no sandbox-dlp service, no WinFsp). Both a CLEAN environment and a DIRTY one
// (some components already present, or a leftover from the old WinFsp/service model)
// converge to the same working state: the CLI on PATH, legacy components removed, and the
// redaction guard reading the user's local vault.

// persistManagedKeeperIni refreshes the secrets-guard-managed keeper.ini from the active
// Keeper profile via the DEFAULT resolution (Windows Credential Manager / current-dir), when
// that profile is reachable. This makes the vault resolve deterministically from EVERY
// terminal — VSCode included — even when the Credential Manager isn't readable in that
// process context: the file is a portable fallback the hook uses via `--ini-file`. Runs on
// the async preload path so it never delays session start; best-effort and silent, and it
// leaves any existing managed config untouched when the default profile isn't reachable
// (so a transient outage doesn't wipe a good file).
func persistManagedKeeperIni() {
	p := managedKeeperIni()
	if p == "" {
		return
	}
	ini, err := vault.ExportKeeperIni()
	if err != nil || strings.TrimSpace(ini) == "" {
		return
	}
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	_ = os.WriteFile(p, []byte(ini), 0o600)
}

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

	// Ensure a vault CLI is available, auto-installing the Keeper CLI if none is present.
	cliOK, cliDetail := ensureVaultCLI()
	fmt.Printf("  • Vault CLI: %s\n", cliDetail)

	prov, ready, detail := vaultStatusBrief(cfg)
	// If a CLI is present but no profile is configured yet, offer to initialize it now by
	// pasting a one-time token (interactive).
	if !ready && cliOK {
		if token := promptKeeperToken(); token != "" {
			fmt.Println("    initializing Keeper profile ...")
			if out, err := vault.InitKeeperProfile(token); err != nil {
				fmt.Fprintf(os.Stderr, "    ✗ profile init failed: %v\n", err)
				if out != "" {
					fmt.Fprintln(os.Stderr, "      "+out)
				}
			} else {
				fmt.Println("    ✓ profile initialized")
			}
			cfg = config.Load(os.Getenv) // re-read in case init set env hints
			prov, ready, detail = vaultStatusBrief(cfg)
		}
	}

	if ready {
		fmt.Printf("  • Vault: %s reachable and VALIDATED (%s) — full redaction guard active\n", prov, detail)
		// Persist the config to a FIXED secrets-guard-managed location so the plugin resolves
		// it deterministically from any terminal (Windows console, VSCode, …) and any working
		// directory — independent of the Windows Credential Manager's per-session readability.
		if prov == "keeper" {
			if ini, e := vault.ExportKeeperIni(); e == nil && strings.TrimSpace(ini) != "" {
				p := managedKeeperIni()
				if e := os.MkdirAll(filepath.Dir(p), 0o700); e == nil {
					if e := os.WriteFile(p, []byte(ini), 0o600); e == nil {
						_ = os.Setenv("KSM_INI_FILE", p)
						fmt.Printf("  • Config: saved to %s (the plugin reads it from every terminal)\n", p)
					} else {
						fmt.Fprintf(os.Stderr, "    ⚠ could not write managed config (%v); relying on the CLI default profile\n", e)
					}
				}
			} else if e != nil {
				fmt.Fprintf(os.Stderr, "    ⚠ could not export config to a portable file (%v); relying on the CLI default profile\n", e)
			}
		}
		if sess := os.Getenv("SG_SESSION"); sess != "" {
			if vals, e := allVaultValues(cfg); e == nil && len(vals) > 0 {
				cache.New().Add(sess, vals)
			}
		}
	} else {
		fmt.Printf("  • Vault: NOT configured/validated — %s\n", detail)
		if h := keeperErrorHint(detail); h != "" {
			fmt.Println("  → " + h)
		} else {
			printKeeperSetupSteps()
		}
	}

	fmt.Println()
	switch {
	case ready:
		fmt.Println("Setup complete and validated — secrets-guard is fully active.")
	case cliOK:
		fmt.Println("Setup almost done — the CLI is ready; initialize your vault (steps above) and re-run.")
	default:
		fmt.Println("Setup incomplete — install a vault CLI and initialize your vault (steps above).")
	}
	if !ready {
		fmt.Println("Note: with require_vault=on (default), prompts are blocked until the vault is configured.")
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
