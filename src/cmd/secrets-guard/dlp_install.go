package main

// Local-model setup & diagnostics. secrets-guard reads the user's own vault (ksm/op) and
// holds the values in the per-session in-memory cache for redaction. There is NO system
// service, NO WinFsp, and NOTHING that requires administrator rights — `dlp-install`,
// `dlp-status` and `doctor` are per-user commands that verify the vault and warm the cache.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/hsoftai/hsoft-claude-plugins/internal/cache"
	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// vaultValueCount resolves the active vault provider and counts the secret values the
// guard would load. No value is ever printed — only the provider name and a count.
func vaultValueCount(cfg config.Config) (provider string, n int, err error) {
	r := vault.NewRunner()
	res, e := vault.Select(cfg.VaultProvider, r, cfg.OPAccount)
	if e != nil {
		return "", 0, e
	}
	if res.ProviderName() == "none" {
		return "", 0, fmt.Errorf("no vault CLI available (install ksm/op and initialize a profile)")
	}
	vals, e := vault.AllSecretValues(r, res.ProviderName())
	if e != nil {
		return res.ProviderName(), 0, fmt.Errorf("vault unreachable (profile not initialized?): %v", e)
	}
	return res.ProviderName(), len(vals), nil
}

// runDLPStatus implements `secrets-guard dlp-status`: reports whether the local redaction
// guard can load values from the user's vault.
func runDLPStatus() {
	cfg := config.Load(os.Getenv)
	prov, n, err := vaultValueCount(cfg)
	if err != nil {
		fmt.Printf("secrets-guard: redaction guard NOT ready — %v\n", err)
		fmt.Println("  run `secrets-guard dlp-install` after initializing your vault profile.")
		os.Exit(1)
	}
	fmt.Printf("secrets-guard: redaction guard ready (provider=%s, %d secret values guardable)\n", prov, n)
}

// runDoctor implements `secrets-guard doctor`: a value-free local diagnostic.
func runDoctor() {
	cfg := config.Load(os.Getenv)
	fmt.Println("secrets-guard doctor —", version)
	fmt.Println("  os:            ", runtime.GOOS)
	fmt.Println("  user:          ", os.Getenv("USERNAME"))
	if p, ok := vault.LookKeeper(); ok {
		fmt.Println("  ksm on PATH:    yes (", p, ")")
	} else if p, err := exec.LookPath("op"); err == nil {
		fmt.Println("  op on PATH:     yes (", p, ")")
	} else {
		fmt.Println("  vault CLI:      NOT on PATH (install KeeperSecurity.KeeperSecretsManager or 1Password CLI)")
	}
	prov, n, err := vaultValueCount(cfg)
	if err != nil {
		fmt.Printf("  vault:          NOT ready — %v\n", err)
		if h := keeperErrorHint(err.Error()); h != "" {
			fmt.Println("  → " + h)
		}
	} else {
		fmt.Printf("  vault:          %s reachable (%d secret values)\n", prov, n)
	}
	fmt.Printf("  options:        preload_secrets=%s guard_required=%s\n",
		cfg.PreloadSecrets, cfg.GuardRequired)
	fmt.Println("  model:          local — ksm/op profile + in-memory cache (no service, no WinFsp, no admin)")
	// The single most common misconfiguration: a reachable vault but preload_secrets=off, so
	// the full-vault cache is never populated and a file/tool read of a secret that was not
	// resolved THIS session is neither redacted nor blocked. Call it out loudly.
	if !cfg.PreloadEnabled() && err == nil {
		fmt.Println("  ⚠ WARNING:      preload_secrets=off — the full-vault redaction guard is DISABLED.")
		fmt.Println("                  A Read/tool output containing a vault secret that was NOT resolved")
		fmt.Println("                  this session will NOT be redacted or blocked. Set preload_secrets=auto")
		fmt.Println("                  (managed-settings: CLAUDE_PLUGIN_OPTION_PRELOAD_SECRETS=auto) to scan")
		fmt.Println("                  every value in the vault against every prompt and tool output.")
	}
	if err != nil && cfg.GuardRequired == "on" {
		fmt.Println("  => guard_required=on and the vault is NOT ready: prompts/tools will be BLOCKED. Fix the vault or set guard_required=auto.")
	} else {
		fmt.Println("  => prompts/tools are allowed; known vault values are redacted (detector-only if the vault isn't ready).")
	}
}

// runDLPInstall implements `secrets-guard dlp-install`: a per-user (NO administrator) setup
// that verifies the local vault and warms the guard cache, reporting success or the exact
// error. It installs nothing system-wide.
func runDLPInstall(cfg config.Config) {
	fmt.Println("secrets-guard: setting up the local redaction guard (per-user, no admin, no service)...")

	_, ksmOK := vault.LookKeeper()
	_, opErr := exec.LookPath("op")
	if !ksmOK && opErr != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard dlp-install: FAILED — no vault CLI (ksm/op) found on PATH.")
		fmt.Fprintln(os.Stderr, "  install Keeper:  winget install KeeperSecurity.KeeperSecretsManager")
		fmt.Fprintln(os.Stderr, "  then initialize:  ksm profile init <one-time-token>")
		fmt.Fprintln(os.Stderr, "  (open a NEW terminal so the CLI is on PATH, then re-run this).")
		os.Exit(1)
	}

	prov, n, err := vaultValueCount(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard dlp-install: FAILED —", err)
		fmt.Fprintln(os.Stderr, "  initialize your vault profile (e.g. `ksm profile init <one-time-token>`) and retry.")
		os.Exit(1)
	}

	// Warm the cache for the current session if one is set (best-effort; SessionStart also
	// preloads automatically).
	if sess := os.Getenv("SG_SESSION"); sess != "" {
		if vals, e := allVaultValues(cfg); e == nil && len(vals) > 0 {
			cache.New().Add(sess, vals)
		}
	}

	fmt.Printf("secrets-guard dlp-install: SUCCESS — %s reachable, %d secret values will be guarded.\n", prov, n)
	fmt.Println("  the guard preloads these into memory at each session start and redacts them from the model.")
	fmt.Println("  verify any time with: secrets-guard doctor")
}
