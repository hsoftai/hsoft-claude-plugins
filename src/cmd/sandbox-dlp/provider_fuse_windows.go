//go:build sandboxdlp && windows

// Windows specifics for the shared FUSE provider (provider_fuse.go), backed by WinFsp.
//
// This is the platform where the per-process property is actually achievable kext-free:
// WinFsp is a signed driver installed once via MSI (no Secure Boot / reduced-security
// dance), and it reports the originating process id to the file system — so the read
// handler can serve the rendered value to ONLY the secrets-guard command's subtree.
//
// ── BUILD (on a Windows host) ────────────────────────────────────────────────────────
//   1. Install WinFsp (https://winfsp.dev) — provides winfsp-x64.dll and the driver.
//   2. Install a cgo toolchain: mingw-w64 gcc (e.g. via msys2/scoop) OR TDM-GCC.
//      Set CGO_ENABLED=1 and ensure gcc is on PATH.
//   3. go build -tags sandboxdlp ./cmd/sandbox-dlp   (cgofuse links WinFsp at runtime)
//   4. go test  -tags sandboxdlp ./cmd/sandbox-dlp   (the provider_fuse tests run here)
//
// ── VERIFY FIRST (the one make-or-break unknown) ─────────────────────────────────────
//   Confirm fuse.Getcontext() in projFS.rendered() returns the REAL requesting process
//   id under WinFsp (not 0, not the service pid). Quick check: run the per-process test
//   (see provider_fuse_windows_test.go scaffold) — an in-subtree reader must get the
//   rendered value while an unrelated process gets the original references. If the pid
//   is wrong, wire the oracle to WinFsp's FspFileSystemOperationProcessId() instead
//   (cgofuse exposes the host; you may need a small addition to read it per-op).
//
// ── MOUNTPOINT ───────────────────────────────────────────────────────────────────────
//   WinFsp mounts onto a directory that must NOT already exist (WinFsp creates it), or a
//   drive letter like "Z:". The client (secrets-guard) passes a temp directory; we remove
//   it here so WinFsp can create it. If directory mounts misbehave in your environment,
//   switch to an unused drive letter (see fuseMountOpts notes).

package main

import (
	"os"
	"path/filepath"
)

func fuseDriverName() string { return "winfsp" }

// prepareMountpoint makes the path suitable for a WinFsp directory mount: the mountpoint
// itself must not exist, but its parent must.
func prepareMountpoint(mp string) error {
	_ = os.Remove(mp) // WinFsp creates the mountpoint; it must be absent
	return os.MkdirAll(filepath.Dir(mp), 0o700)
}

// fuseMountOpts returns the WinFsp/cgofuse mount options. Caching is disabled so the
// per-process read decision is honored on every read rather than cached after the first
// reader (the same reason macOS uses attr_timeout=0).
//
// WinFsp's FUSE compatibility layer accepts these -o options; tune on Windows:
//   - uid=-1,gid=-1        : present files as owned by the caller.
//   - FileInfoTimeout=0    : do not cache file attributes (critical for per-read gating).
//   - DirInfoTimeout=0     : do not cache directory listings.
//   - VolumeInfoTimeout=0  : do not cache volume info.
//   - (optional) ExactFileSystemName, volname, etc.
//
// If you prefer a drive-letter mount instead of a directory mount, pass the letter as the
// mountpoint (e.g. "Z:") from the client and drop prepareMountpoint's remove.
func fuseMountOpts(mountpoint string) []string {
	return []string{
		"-o", "uid=-1",
		"-o", "gid=-1",
		"-o", "FileInfoTimeout=0",
		"-o", "DirInfoTimeout=0",
		"-o", "VolumeInfoTimeout=0",
	}
}
