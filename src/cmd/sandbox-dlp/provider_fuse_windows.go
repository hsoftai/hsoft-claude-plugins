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
// ── CALLER PID (resolved) ────────────────────────────────────────────────────────────
//   WinFsp exposes the originating process id only to Create/Open/Rename, NOT to Read
//   (a Windows limitation; FspFileSystemOperationProcessId reads the same token and is
//   likewise empty during Read). So the provider captures the pid in Open/Create — keyed
//   to the returned file handle — and Read/Getattr resolve it via callerPID(fh) below.
//   See provider_fuse.go (openHandle) and the "Windows implementation notes" in
//   docs/sandbox-dlp.md. The per-process test proves the result.
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

// callerPID returns the pid captured for fh at Open/Create/Opendir time. WinFsp does NOT
// expose the originating pid during Read (only Create/Open/Rename), so the per-read
// decision must use the pid recorded when the handle was opened. An unknown fh (e.g. a
// path-only Getattr with no open handle) fails closed: -1 is never in any subtree, so the
// provider serves the original references.
func (p *projFS) callerPID(fh uint64) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pid, ok := p.handles[fh]; ok {
		return pid
	}
	return -1
}

// isDriveLetter reports whether mp is a bare drive-letter mountpoint like "Z:".
func isDriveLetter(mp string) bool {
	return len(mp) == 2 && mp[1] == ':'
}

// prepareMountpoint makes the path suitable for the WinFsp mount. For a drive letter
// (the default, so native modules load — see dlp_mount_windows.go) there is nothing to
// prepare: WinFsp creates the volume at the letter. For a directory mount the mountpoint
// itself must not exist (WinFsp creates it) while its parent must.
func prepareMountpoint(mp string) error {
	if isDriveLetter(mp) {
		return nil
	}
	_ = os.Remove(mp)
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
		// NOTE: -o direct_io would force every read through the handler (ideal for the
		// per-process ref-file gate), but it also disables the cache that Windows needs to
		// memory-map image sections — so DLL / native-addon (.node) loads from the mount
		// fail with ACCESS_DENIED and real toolchains (Next.js/SWC) can't run. We rely on
		// FileInfoTimeout=0 instead; the per-read gate is still honored because the read
		// handler resolves the caller per file-handle on every Read (validated by the
		// per-process test).
	}
}
