//go:build windows

package broker

// Windows has no O_NOFOLLOW; symlink creation there requires privileges and the
// Cowork broker host is macOS/Linux. O_EXCL still prevents reusing a planted node.
const oNoFollow = 0
