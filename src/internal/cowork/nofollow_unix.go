//go:build !windows

package cowork

import "syscall"

// oNoFollow makes os.OpenFile fail if the final path component is a symlink, so a
// VM-planted symlink in the shared spool cannot redirect a host write outside it.
const oNoFollow = syscall.O_NOFOLLOW
