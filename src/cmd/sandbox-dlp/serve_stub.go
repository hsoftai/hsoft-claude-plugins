//go:build !darwin && !windows

package main

import (
	"fmt"
	"os"
)

// On platforms whose control transport is not implemented yet (Windows uses a named
// pipe, added with the WinFsp provider), serve/status report that cleanly instead of
// failing to build.
func runServe() {
	fmt.Fprintln(os.Stderr, "sandbox-dlp: serve is not implemented on this platform yet")
	os.Exit(1)
}

func runStatus() {
	fmt.Println("sandbox-dlp: not running (platform not supported yet)")
	os.Exit(1)
}
