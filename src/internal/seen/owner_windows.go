//go:build windows

package seen

import "io/fs"

// ownedByUs is a no-op on Windows: the per-user temp dir already isolates users,
// and the unix uid/permission model does not apply.
func ownedByUs(fi fs.FileInfo) bool { return true }

// permOK is always true on Windows: Go reports directory mode bits as 0777 regardless of
// the real ACL, so the unix 0700 check is meaningless here. Isolation comes from the
// per-user %LOCALAPPDATA%\Temp location (ACL-protected against other users) instead.
func permOK(fs.FileInfo) bool { return true }
