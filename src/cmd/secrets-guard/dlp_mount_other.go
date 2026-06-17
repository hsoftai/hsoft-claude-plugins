//go:build !windows

package main

import "os"

// chooseMountpoint creates a per-exec temp directory for the projection mount (macOS dev).
// The mount target and the working directory are the same directory.
func chooseMountpoint() (mount, cwd string, cleanup func(), err error) {
	mp, err := os.MkdirTemp(shortTmp(), "sgmnt")
	if err != nil {
		return "", "", nil, err
	}
	return mp, mp, func() { _ = os.RemoveAll(mp) }, nil
}
