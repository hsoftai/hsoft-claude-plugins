//go:build sandboxdlp && (darwin || windows)

// Shared FUSE-protocol provider for macOS (macFUSE/fuse-t) and Windows (WinFsp), built
// only with the `sandboxdlp` tag (requires the driver + cgofuse). It presents a loopback
// view of the backing project at the per-exec mountpoint and, for DECLARED ref-files,
// serves the RENDERED bytes from the projection registry to ONLY the authorized process
// subtree; every other caller and every non-ref path passes straight through to the real
// backing. The rendered value is therefore never written to disk and never visible to a
// process outside the subtree.
//
// Per-OS differences (driver name, mount options, mountpoint preparation) live in
// provider_fuse_darwin.go and provider_fuse_windows.go.
//
// IMPORTANT for the Windows port — the whole per-process property hinges on the read
// handler seeing the REAL requesting process id:
//   - macFUSE delivers it via fuse.Getcontext() (verified: macFUSE; fuse-t reports 0).
//   - WinFsp delivers the originating process id; cgofuse SHOULD surface it through
//     fuse.Getcontext()'s pid. VERIFY THIS FIRST on Windows. If Getcontext() returns 0
//     or the service pid, switch the oracle input to WinFsp's
//     FspFileSystemOperationProcessId() (exposed via the WinFsp host) — that is the
//     authoritative source on Windows.

package main

import (
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/winfsp/cgofuse/fuse"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// lastCallerPID records the PID the driver reported for the most recent ref-file read,
// so integration tests can detect a driver that does not propagate the caller PID
// (fuse-t reports 0). On a correct driver (macFUSE, WinFsp) it is the real reader.
var lastCallerPID int32

// projFS is a loopback filesystem over root, with a per-process override for ref-files.
type projFS struct {
	fuse.FileSystemBase
	root string
	reg  *projection.Registry
}

// backing maps a mount-relative FUSE path to its absolute backing path.
func (p *projFS) backing(path string) string {
	return filepath.Join(p.root, filepath.FromSlash(path))
}

// rendered returns the rendered bytes the CURRENT caller should see for path, if path is
// a declared ref-file and the caller is in the authorized subtree.
func (p *projFS) rendered(path string) ([]byte, bool) {
	_, _, pid := fuse.Getcontext()
	atomic.StoreInt32(&lastCallerPID, int32(pid))
	return p.reg.Resolve(p.backing(path), pid)
}

func (p *projFS) Getattr(path string, stat *fuse.Stat_t, fh uint64) int {
	fi, err := os.Lstat(p.backing(path))
	if err != nil {
		return -fuse.ENOENT
	}
	fillStat(stat, fi)
	// A served ref-file must report the RENDERED length, or reads get truncated/padded.
	if content, ok := p.rendered(path); ok {
		stat.Size = int64(len(content))
	}
	return 0
}

func (p *projFS) Open(path string, flags int) (int, uint64) { return 0, 0 }

func (p *projFS) Read(path string, buff []byte, ofst int64, fh uint64) int {
	if content, ok := p.rendered(path); ok {
		if ofst >= int64(len(content)) {
			return 0
		}
		return copy(buff, content[ofst:])
	}
	f, err := os.Open(p.backing(path))
	if err != nil {
		return -fuse.EIO
	}
	defer f.Close()
	n, _ := f.ReadAt(buff, ofst)
	return n
}

func (p *projFS) Opendir(path string) (int, uint64) { return 0, 0 }

func (p *projFS) Readdir(path string, fill func(name string, stat *fuse.Stat_t, ofst int64) bool, ofst int64, fh uint64) int {
	entries, err := os.ReadDir(p.backing(path))
	if err != nil {
		return -fuse.ENOENT
	}
	fill(".", nil, 0)
	fill("..", nil, 0)
	for _, e := range entries {
		if !fill(e.Name(), nil, 0) {
			break
		}
	}
	return 0
}

// fillStat copies the fields the kernel needs from an os.FileInfo (portable across
// macFUSE and WinFsp — no platform-specific stat struct).
func fillStat(dst *fuse.Stat_t, fi os.FileInfo) {
	mode := uint32(fi.Mode().Perm())
	if fi.IsDir() {
		mode |= fuse.S_IFDIR
	} else {
		mode |= fuse.S_IFREG
	}
	dst.Mode = mode
	dst.Size = fi.Size()
	ts := fuse.NewTimespec(fi.ModTime())
	dst.Mtim, dst.Atim, dst.Ctim = ts, ts, ts
	dst.Nlink = 1
}

// fuseMounter spins a per-exec FUSE host (macFUSE/fuse-t or WinFsp) over the backing.
type fuseMounter struct{}

func newMounter() mounter { return fuseMounter{} }

func (fuseMounter) Name() string { return fuseDriverName() }

func (fuseMounter) Mount(execID, mountpoint, root string, reg *projection.Registry) (func() error, error) {
	if err := prepareMountpoint(mountpoint); err != nil {
		return nil, err
	}
	fs := &projFS{root: root, reg: reg}
	host := fuse.NewFileSystemHost(fs)
	opts := fuseMountOpts(mountpoint)
	done := make(chan struct{})
	go func() {
		host.Mount(mountpoint, opts) // blocks until Unmount
		close(done)
	}()
	unmount := func() error {
		host.Unmount()
		<-done
		return nil
	}
	return unmount, nil
}
