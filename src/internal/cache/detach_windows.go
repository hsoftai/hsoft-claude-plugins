//go:build windows

package cache

import (
	"os/exec"
	"syscall"
)

// detach starts the daemon in a new process group so it outlives the hook.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200} // CREATE_NEW_PROCESS_GROUP
}
