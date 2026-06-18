//go:build !windows

package main

import (
	"os"
	"syscall"
)

// processAlive reports whether pid is a live process (signal 0 probes existence without
// delivering a signal). Used by the reaper to drop execs whose owning sandbox process died.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
