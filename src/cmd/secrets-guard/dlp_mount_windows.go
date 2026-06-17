//go:build windows

package main

import (
	"fmt"
	"os"
)

// chooseMountpoint picks an unused drive letter (e.g. "Z:") for the WinFsp projection and
// returns the mount target ("Z:") plus the working directory to run the command in
// ("Z:\\", an absolute path the child process can chdir into).
//
// Why a drive letter and not a temp directory: a directory mount is a reparse point, and
// Windows refuses to memory-map image sections (load DLLs / native .node addons) from it
// with ACCESS_DENIED — which breaks real toolchains (Next.js/SWC, anything with native
// deps) running under the mount. A drive-letter mount is a first-class local volume, so
// image loading works. Nothing to clean up afterward (the letter is freed on unmount).
func chooseMountpoint() (mount, cwd string, cleanup func(), err error) {
	for c := 'Z'; c >= 'F'; c-- {
		letter := string(c) + ":"
		if _, e := os.Stat(letter + `\`); os.IsNotExist(e) {
			return letter, letter + `\`, func() {}, nil
		}
	}
	return "", "", nil, fmt.Errorf("no free drive letter for the DLP mount")
}
