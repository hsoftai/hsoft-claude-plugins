package main

import (
	"os"
	"path/filepath"
)

// ensureKeeperConfig points the Keeper `ksm` CLI at the user's INI config (via KSM_INI_FILE)
// when it lives in a standard per-user location, so secrets-guard's `ksm` invocations find
// it regardless of the working directory. ksm only looks for `keeper.ini` in the CURRENT
// directory by default, so a profile initialized to `~/.keeper/keeper.ini` (or `~/keeper.ini`)
// is otherwise invisible when ksm runs from a project directory — the SDK then reports "The
// Keeper SDK client has not been loaded. The INI config might not be set." An explicit
// KSM_CONFIG (base64) or KSM_INI_FILE is respected as-is.
func ensureKeeperConfig() {
	if os.Getenv("KSM_CONFIG") != "" || os.Getenv("KSM_INI_FILE") != "" {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	for _, p := range []string{
		filepath.Join(home, ".keeper", "keeper.ini"),
		filepath.Join(home, "keeper.ini"),
	} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			os.Setenv("KSM_INI_FILE", p)
			return
		}
	}
}
