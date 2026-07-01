package main

import (
	"os"
	"path/filepath"
)

// managedKeeperIni is the FIXED, secrets-guard-owned location where `secrets-guard install`
// persists the Keeper config. The plugin reads exactly this path so resolution is
// deterministic and identical from every terminal (Windows console, VSCode, etc.) and every
// working directory — independent of the Windows Credential Manager (whose readability can
// vary by process/session) and of any stray `~/.keeper/keeper.ini`.
func managedKeeperIni() string {
	base := os.Getenv("LOCALAPPDATA") // Windows
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "secrets-guard", "keeper.ini")
}

// ensureKeeperConfig points the Keeper `ksm` CLI at the secrets-guard-managed INI config (via
// KSM_INI_FILE) so `ksm` invocations resolve it regardless of the working directory. It uses
// ONLY the managed location written by `secrets-guard install` — it deliberately does NOT
// auto-detect `~/.keeper/keeper.ini` or `~/keeper.ini`, because a stale or foreign keeper.ini
// there would SHADOW a working profile (e.g. the Windows Credential Manager one) and cause
// "access_denied / Unable to validate Keeper application access". An explicit KSM_CONFIG
// (base64) or KSM_INI_FILE set by the user/operator is respected as-is.
func ensureKeeperConfig() {
	if os.Getenv("KSM_CONFIG") != "" || os.Getenv("KSM_INI_FILE") != "" {
		return
	}
	if p := managedKeeperIni(); p != "" {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			os.Setenv("KSM_INI_FILE", p)
		}
	}
}
