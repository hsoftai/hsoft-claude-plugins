//go:build !windows

package seen

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByUs reports whether fi is owned by the current uid. On a multi-user host
// this rejects a ledger directory pre-planted by another user (which would
// otherwise silently disable the resolved-value leak backstop).
func ownedByUs(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true // cannot determine — do not block on platforms without stat
	}
	return int(st.Uid) == os.Getuid()
}

// permOK enforces the 0700 (no group/other access) requirement on Unix, where a
// world-known /tmp path could otherwise be pre-planted by another user.
func permOK(fi fs.FileInfo) bool { return fi.Mode().Perm()&0o077 == 0 }
