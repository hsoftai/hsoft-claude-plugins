//go:build sandboxdlp && darwin

// macOS specifics for the shared FUSE provider (provider_fuse.go).
//
// NOTE: macOS shipped with the in-place renderer in production (SIP prevents a robust
// kext-free per-process substitution, and macFUSE needs a kext install users can't be
// asked to do). This provider is kept for development / an optional macFUSE "full
// coverage" mode and was used to validate the projection mechanics against fuse-t.
// Build/test with: go test -tags sandboxdlp ./cmd/sandbox-dlp/

package main

import (
	"os"

	"github.com/winfsp/cgofuse/fuse"
)

func fuseDriverName() string { return "macfuse" }

// callerPID reads the originating pid live from the FUSE context. macFUSE delivers it to
// every operation (including Read), so darwin keeps the validated per-read source rather
// than the handle-captured pid Windows must use. fh is unused here.
func (p *projFS) callerPID(fh uint64) int {
	_, _, pid := fuse.Getcontext()
	return pid
}

// macFUSE wants the mountpoint directory to exist.
func prepareMountpoint(mp string) error { return os.MkdirAll(mp, 0o700) }

// Caching disabled so the per-process read decision is re-evaluated on every read.
func fuseMountOpts(mountpoint string) []string {
	return []string{
		"-o", "attr_timeout=0",
		"-o", "entry_timeout=0",
		"-o", "noubc",
		"-o", "direct_io",
		"-o", "volname=secrets-guard",
	}
}
