//go:build !windows

package main

import "path/filepath"

// The legacy WinFsp/sandbox-dlp service + "fake DLP server" workaround were Windows-only,
// so there are no stale components to detect or remove off Windows.

func staleComponents() []string { return nil }
func removeStale() []string     { return nil }

// uninstallEnv removes the per-user CLI on macOS/Linux. The PATH line lives in the shell rc
// and is left in place (editing a user's rc destructively on uninstall is riskier than a
// harmless dangling entry); a note is printed by the caller.
func uninstallEnv() []string {
	if removeIfExists(filepath.Join(installTargetDir(), installBinName())) {
		return []string{"secrets-guard CLI binary"}
	}
	return nil
}
