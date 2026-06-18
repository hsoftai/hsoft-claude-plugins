//go:build windows

package main

import "golang.org/x/sys/windows"

// processAlive reports whether pid is a live process. Used by the reaper to drop execs
// whose owning sandbox process has died. A false negative (a process that happened to exit
// with code 259) is harmless: the exec's TTL reaps it later, and the Job Object oracle
// keeps the per-read gating correct regardless.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259 // STILL_ACTIVE
	return code == stillActive
}
