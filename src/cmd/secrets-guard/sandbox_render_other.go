//go:build !linux

package main

import "fmt"

// renderFiles is Linux-only (it needs mount namespaces + bind mounts). On other
// platforms file rendering is unavailable; the caller renders the environment only
// and leaves files untouched. This stub is never reached through the normal flow
// because the namespace path is gated on runtime.GOOS == "linux".
func renderFiles(_ []refFile, _ map[string]string) error {
	return fmt.Errorf("file rendering is only available on Linux")
}
