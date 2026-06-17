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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/winfsp/cgofuse/fuse"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// lastCallerPID records the PID the driver reported for the most recent ref-file read,
// so integration tests can detect a driver that does not propagate the caller PID
// (fuse-t reports 0). On a correct driver (macFUSE, WinFsp) it is the real reader.
var lastCallerPID int32

// projFS is a loopback filesystem over root, with a per-process override for ref-files.
//
// Caller identity per read is resolved by p.callerPID(fh), whose implementation is
// per-OS (provider_fuse_{windows,darwin}.go):
//   - macFUSE delivers the originating pid to every operation, so darwin reads it live
//     with fuse.Getcontext().
//   - WinFsp only delivers the originating pid to Create/Open/Rename (a Windows
//     limitation: the cache manager decouples reads from the originating process), NOT to
//     Read. So on Windows we CAPTURE the pid in Open/Create and key it to the returned
//     file handle (fh); Read and the post-open Getattr then look it up by fh. (Wiring the
//     oracle to FspFileSystemOperationProcessId() would not help — it reads the same
//     request token that is absent during Read.)
type projFS struct {
	fuse.FileSystemBase
	root string
	reg  *projection.Registry

	mu      sync.Mutex
	handles map[uint64]int // fh -> caller pid captured at Open/Create/Opendir
	nextFH  uint64
}

// openHandle allocates a file handle and records the CURRENT caller's pid against it.
// It is called from the operations where the driver is guaranteed to expose the real
// originating pid (Open/Create/Opendir on both macFUSE and WinFsp).
func (p *projFS) openHandle() uint64 {
	_, _, pid := fuse.Getcontext()
	p.mu.Lock()
	p.nextFH++
	if p.nextFH == 0 {
		// Wrap-around: handle 0 must never be allocated, since a stale handle 0
		// (never freed after a crash/force-unmount) would be silently reused and
		// rebind a new caller's pid over the old entry. Reaching 2^64 opens should
		// never occur in practice and indicates a severe resource leak.
		p.mu.Unlock()
		panic("handle allocation overflow: 2^64 file opens exceeded")
	}
	fh := p.nextFH
	p.handles[fh] = pid
	p.mu.Unlock()
	return fh
}

// freeHandle drops a handle's recorded pid on Release/Releasedir.
func (p *projFS) freeHandle(fh uint64) {
	p.mu.Lock()
	delete(p.handles, fh)
	p.mu.Unlock()
}

// backing maps a mount-relative FUSE path to its absolute backing path.
func (p *projFS) backing(path string) string {
	return filepath.Join(p.root, filepath.FromSlash(path))
}

// rendered returns the rendered bytes the caller behind fh should see for path, if path
// is a declared ref-file and that caller is in the authorized subtree. fh selects the
// caller identity captured at open time (see projFS doc); for an operation with no handle
// (e.g. a path-only Getattr) callerPID returns a fail-closed pid so we serve references.
func (p *projFS) rendered(path string, fh uint64) ([]byte, bool) {
	pid := p.callerPID(fh)
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
	// This is honored on the post-open Getattr (valid fh → known caller); a path-only
	// Getattr reports the backing length, which is corrected once the file is opened.
	if content, ok := p.rendered(path, fh); ok {
		stat.Size = int64(len(content))
	}
	return 0
}

func (p *projFS) Open(path string, flags int) (int, uint64) { return 0, p.openHandle() }

// Create makes the file on the backing (so the app's writes persist to the real project),
// and captures the caller pid (WinFsp exposes it here) so a create-disposition open of a
// ref-file still goes through the per-process read gate.
func (p *projFS) Create(path string, flags int, mode uint32) (int, uint64) {
	backing := p.backing(path)
	// Check-and-create atomically (see Truncate): the registry lock spans the managed
	// check and os.OpenFile, so the path cannot become a declared ref-file in the window
	// between the check and the create/truncate. A managed path is refused (fail-closed),
	// so a ref-file is never created or truncated over through the mount.
	err, ok := p.reg.MutateIfUnmanaged(func() error {
		f, err := os.OpenFile(backing, os.O_CREATE|os.O_RDWR, os.FileMode(mode).Perm())
		if err != nil {
			return err
		}
		return f.Close()
	}, backing)
	if !ok {
		return -fuse.EACCES, ^uint64(0)
	}
	if err != nil {
		return errno(err), ^uint64(0)
	}
	return 0, p.openHandle()
}

func (p *projFS) Release(path string, fh uint64) int {
	p.freeHandle(fh)
	return 0
}

// ── Write passthrough ────────────────────────────────────────────────────────────────
// The projection is a live loopback: writes to ordinary files land on the real backing so
// real commands (builds, dev servers) work under the mount. Declared ref-files are the
// exception — any write/rename/remove of one is refused, so the rendered secret value can
// never be persisted and the on-disk reference file is never altered through the mount.

// errno maps an os error to a FUSE return code, so callers (Node's recursive mkdir, atomic
// rename-over, etc.) see EEXIST/ENOENT/EACCES rather than a blanket EIO they can't handle.
func errno(err error) int {
	switch {
	case err == nil:
		return 0
	case os.IsExist(err):
		return -fuse.EEXIST
	case os.IsNotExist(err):
		return -fuse.ENOENT
	case os.IsPermission(err):
		return -fuse.EACCES
	default:
		return -fuse.EIO
	}
}

func (p *projFS) Write(path string, buff []byte, ofst int64, fh uint64) int {
	backing := p.backing(path)
	// Check-and-write atomically (see Truncate): the registry lock spans the managed check
	// and the WriteAt, so the path cannot become a declared ref-file in the window between
	// the check and the write (defeats the register-after-check TOCTOU). A managed path is
	// refused (fail-closed), so no bytes are ever persisted to a rendered ref-file.
	var n int
	err, ok := p.reg.MutateIfUnmanaged(func() error {
		f, err := os.OpenFile(backing, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		n, err = f.WriteAt(buff, ofst)
		return err
	}, backing)
	if !ok {
		return -fuse.EACCES
	}
	// FUSE semantics: on a partial write (n>0 with an error) return the byte count so the
	// client tracks progress correctly; only convert to an errno when nothing was written.
	if err != nil && n == 0 {
		return errno(err)
	}
	return n
}

func (p *projFS) Truncate(path string, size int64, fh uint64) int {
	backing := p.backing(path)
	// Check-and-truncate atomically: the registry holds its lock across the managed check
	// and os.Truncate, so the path cannot become a declared ref-file in between (defeats
	// the register-after-check TOCTOU). A managed path is refused (fail-closed).
	err, ok := p.reg.MutateIfUnmanaged(func() error { return os.Truncate(backing, size) }, backing)
	if !ok {
		return -fuse.EACCES
	}
	return errno(err)
}

func (p *projFS) Mkdir(path string, mode uint32) int {
	return errno(os.Mkdir(p.backing(path), os.FileMode(mode).Perm()))
}

func (p *projFS) Unlink(path string) int {
	backing := p.backing(path)
	// Check-and-remove atomically (see Truncate): the registry lock spans the managed
	// check and os.Remove, so a path that becomes a ref-file cannot be deleted out from
	// under the protection. A managed path is refused (fail-closed).
	err, ok := p.reg.MutateIfUnmanaged(func() error { return os.Remove(backing) }, backing)
	if !ok {
		return -fuse.EACCES
	}
	return errno(err)
}

func (p *projFS) Rmdir(path string) int {
	return errno(os.Remove(p.backing(path)))
}

func (p *projFS) Rename(oldpath, newpath string) int {
	oldBacking, newBacking := p.backing(oldpath), p.backing(newpath)
	// Check-and-rename atomically (see Truncate): the registry lock spans the managed
	// check of BOTH paths and os.Rename, so neither side can become a declared ref-file
	// in the window — a rename can't move a ref-file or overwrite one. Refuse if either is
	// managed (fail-closed).
	err, ok := p.reg.MutateIfUnmanaged(func() error { return os.Rename(oldBacking, newBacking) }, oldBacking, newBacking)
	if !ok {
		return -fuse.EACCES
	}
	return errno(err)
}

// Chmod is a no-op success: Windows backing files carry no POSIX mode, and refusing it
// would break tools that chmod after writing.
func (p *projFS) Chmod(path string, mode uint32) int { return 0 }

func (p *projFS) Utimens(path string, tmsp []fuse.Timespec) int {
	backing := p.backing(path)
	// Check-and-chtimes atomically (see Truncate): the registry lock spans the managed
	// check and os.Chtimes, so the path cannot become a declared ref-file in between. A
	// managed path is refused (fail-closed), so a ref-file's timestamps are never altered
	// through the mount.
	err, ok := p.reg.MutateIfUnmanaged(func() error {
		if len(tmsp) >= 2 {
			atime := time.Unix(tmsp[0].Sec, tmsp[0].Nsec)
			mtime := time.Unix(tmsp[1].Sec, tmsp[1].Nsec)
			return os.Chtimes(backing, atime, mtime)
		}
		return nil
	}, backing)
	if !ok {
		return -fuse.EACCES
	}
	return errno(err)
}

func (p *projFS) Flush(path string, fh uint64) int                   { return 0 }
func (p *projFS) Fsync(path string, datasync bool, fh uint64) int    { return 0 }
func (p *projFS) Fsyncdir(path string, datasync bool, fh uint64) int { return 0 }

// Access allows everything: the per-process secret gate lives in Read; file access itself
// mirrors the backing, which the user already owns.
func (p *projFS) Access(path string, mask uint32) int { return 0 }

// Statfs reports ample free space so tools that check disk space before writing (npm,
// webpack, next) don't refuse to run on the projection. The numbers are advisory; real
// writes pass through to the backing volume.
func (p *projFS) Statfs(path string, stat *fuse.Statfs_t) int {
	const block = 4096
	stat.Bsize = block
	stat.Frsize = block
	stat.Blocks = 1 << 32
	stat.Bfree = 1 << 32
	stat.Bavail = 1 << 32
	stat.Files = 1 << 24
	stat.Ffree = 1 << 24
	stat.Favail = 1 << 24
	stat.Namemax = 255
	return 0
}

func (p *projFS) Read(path string, buff []byte, ofst int64, fh uint64) int {
	if content, ok := p.rendered(path, fh); ok {
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

func (p *projFS) Opendir(path string) (int, uint64) { return 0, p.openHandle() }

func (p *projFS) Releasedir(path string, fh uint64) int {
	p.freeHandle(fh)
	return 0
}

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
	fs := &projFS{root: root, reg: reg, handles: map[uint64]int{}}
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
	// The mount comes up asynchronously (WinFsp creates the mountpoint when it starts
	// serving). Block until it is actually answering before returning, so a client that
	// chdirs into the mountpoint right after a successful Register never races the mount.
	if err := waitMountReady(mountpoint, done, 15*time.Second); err != nil {
		_ = unmount()
		return nil, err
	}
	return unmount, nil
}

// waitMountReady returns once the mountpoint answers a directory listing, or errors if the
// mount goroutine exits first or the deadline passes. On macFUSE the mountpoint exists up
// front so this returns promptly; on WinFsp it blocks until the volume is serving.
func waitMountReady(mountpoint string, done <-chan struct{}, timeout time.Duration) error {
	// A bare drive-letter mount ("Z:") is drive-relative for ReadDir; probe its root.
	probe := mountpoint
	if len(probe) == 2 && probe[1] == ':' {
		probe += string(os.PathSeparator)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return fmt.Errorf("mount exited before it became ready")
		default:
		}
		if _, err := os.ReadDir(probe); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("mount did not become ready within %s", timeout)
}
