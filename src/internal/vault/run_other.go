//go:build !windows

package vault

import "os/exec"

// vaultCommand runs the vault CLI directly (no batch-wrapper echo issue off Windows).
func vaultCommand(name string, args []string) *exec.Cmd {
	return exec.Command(name, args...)
}
