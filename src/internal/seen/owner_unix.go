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
