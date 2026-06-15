//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// renderFiles renders each ref-file (references → values) into a private in-memory
// tmpfs and bind-mounts it over the original, inside the CURRENT mount namespace
// (the caller has already entered an `unshare --user --map-root-user --mount`
// namespace, where it holds CAP_SYS_ADMIN). Secrets never touch the real disk: the
// rendered copies live only in the tmpfs, and the bind-mounts plus the tmpfs are all
// private to this namespace and vanish when it is torn down (kernel-guaranteed on
// process exit/crash).
//
// Path safety (anti-TOCTOU): each target is opened once with O_NOFOLLOW (a
// final-component symlink swap fails the open → the file is skipped), its truly
// resolved path is validated to be under cwd via /proc/self/fd, and the bind-mount
// is applied over /proc/self/fd/<fd> — i.e. over the exact inode we opened and read,
// never a path re-resolved at mount time. This closes the check-then-use race on the
// read and the mount target.
func renderFiles(files []refFile, values map[string]string) (func(), error) {
	noop := func() {}
	// Make this namespace's mount tree private so nothing propagates to the host.
	_ = syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "")

	dir, err := os.MkdirTemp("", "sg-render-")
	if err != nil {
		return noop, err
	}
	if err := syscall.Mount("tmpfs", dir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0700"); err != nil {
		return noop, fmt.Errorf("tmpfs: %w", err)
	}
	_ = syscall.Mount("", dir, "", syscall.MS_PRIVATE, "")

	cwdReal := realCwd()
	seen := map[devIno]bool{}
	i := 0
	for _, f := range files {
		i += renderOne(f.path, dir, i, cwdReal, values, seen)
	}
	// The bind-mounts + tmpfs are private to this namespace and the kernel discards
	// them when it exits — nothing to restore.
	return noop, nil
}

// devIno identifies a file by device + inode so a file reachable via two paths is
// rendered once and cross-filesystem inode collisions do not skip a distinct file.
type devIno struct{ dev, ino uint64 }

// renderOne opens, validates, renders and binds a single file. It returns 1 if it
// consumed a tmpfs slot index (so the caller advances i), else 0.
func renderOne(path, tmpdir string, idx int, cwdReal string, values map[string]string, seen map[devIno]bool) int {
	// O_NOFOLLOW: a final-component symlink swap after discovery fails the open.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	// Validate the TRULY resolved path (follows parent symlinks) is under cwd.
	actual, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil || !underDir(actual, cwdReal) {
		return 0
	}
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return 0
	}
	key := devIno{uint64(st.Dev), st.Ino}
	if seen[key] {
		return 0
	}
	seen[key] = true

	data, err := io.ReadAll(f)
	if err != nil {
		return 0
	}
	rendered := renderRefs(string(data), values)
	if rendered == string(data) {
		return 0 // no resolvable reference in this file
	}
	src := filepath.Join(tmpdir, fmt.Sprintf("f%d", idx))
	if werr := os.WriteFile(src, []byte(rendered), 0o600); werr != nil {
		return 0
	}
	// Bind over the EXACT inode we opened (via its /proc/self/fd entry), so the mount
	// target cannot be re-resolved to a different path between validation and mount.
	_ = syscall.Mount(src, "/proc/self/fd/"+strconv.Itoa(fd), "", syscall.MS_BIND, "")
	return 1
}

func realCwd() string {
	d := cwd()
	if r, err := filepath.EvalSymlinks(d); err == nil {
		return r
	}
	return d
}

func underDir(path, dir string) bool {
	if dir == "" {
		return false
	}
	return path == dir || strings.HasPrefix(path, dir+string(os.PathSeparator))
}
