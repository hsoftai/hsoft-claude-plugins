//go:build !windows

package cache

import (
	"os/exec"
	"syscall"
)

// detach makes the daemon a new session leader so it survives the hook process.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
