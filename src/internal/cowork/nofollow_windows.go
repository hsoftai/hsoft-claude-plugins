//go:build windows

package cowork

// Windows has no O_NOFOLLOW; the Cowork host is macOS/Linux. O_EXCL still prevents
// reusing a planted node.
const oNoFollow = 0
