//go:build windows

package seen

import "io/fs"

// ownedByUs is a no-op on Windows: the per-user temp dir already isolates users,
// and the unix uid/permission model does not apply. The 0700-perm check in
// verifyOwned is the portable guard.
func ownedByUs(fi fs.FileInfo) bool { return true }
