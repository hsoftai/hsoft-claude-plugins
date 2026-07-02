package main

import (
	"os"
	"path/filepath"
)

// selfInstall copies the running binary into a user-level directory that is on
// the developer's terminal PATH, so `secrets-guard` works in their own shell —
// with NO administrator rights, on Linux, macOS and Windows. It is the mechanism
// behind both the `secrets-guard install` command and the automatic install run
// from the SessionStart hook, so that merely installing/enabling the plugin
// (including when enforced via managed-settings.json) is enough.
//
// It is idempotent: it only re-copies when the source binary changed (newer or a
// different size), and it ensures the destination directory is on the user PATH
// in a platform-appropriate, no-admin way (shell rc on Unix, HKCU registry on
// Windows). When quiet, it returns errors without side output (used by the hook).
//
// If dir is empty the platform default is used (installTargetDir). Returns the
// installed binary's path.
func selfInstall(dir string, quiet bool) (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		src = resolved
	}
	if dir == "" {
		dir = installTargetDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, installBinName())

	// Best-effort cleanup of any leftover displaced binaries from a previous busy
	// replace (see below). They are no longer referenced once this returns.
	cleanupDisplaced(dir)

	if fileChanged(src, dst) {
		tmp := dst + ".tmp"
		if err := copyFile(src, tmp, 0o755); err != nil {
			return dst, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			// The destination is likely busy: another session's CLI is running and
			// Windows refuses to overwrite a loaded image in place. Windows DOES
			// allow renaming a running executable, so displace the stale binary and
			// move the fresh one into its place — the next process launch picks up
			// the new version instead of silently keeping the old one (which caused
			// `doctor` to report a version behind the plugin).
			displaced := dst + ".old"
			_ = os.Remove(displaced)
			if renErr := os.Rename(dst, displaced); renErr == nil {
				if err2 := os.Rename(tmp, dst); err2 != nil {
					// Couldn't put the new one in place; restore the old and keep it.
					_ = os.Rename(displaced, dst)
					os.Remove(tmp)
				}
				// The displaced copy may still be locked by the running process; it is
				// removed on the next selfInstall via cleanupDisplaced.
			} else {
				os.Remove(tmp)
				// Could not even displace it. If a copy exists, keep it; otherwise
				// surface the original error.
				if _, statErr := os.Stat(dst); statErr != nil {
					return dst, err
				}
			}
		}
	}

	if err := ensureOnUserPath(dir, quiet); err != nil {
		return dst, err
	}
	return dst, nil
}

// cleanupDisplaced removes the `<bin>.old` displaced-binary left behind when a
// prior selfInstall replaced a busy (locked) executable. It is best-effort: if
// the file is still locked by a running process the removal fails silently and
// is retried on the next call.
func cleanupDisplaced(dir string) {
	os.Remove(filepath.Join(dir, installBinName()+".old"))
}

// fileChanged reports whether src should be (re)copied to dst: true when dst is
// missing, a different size, or older than src. Cheap (stat only) so it is safe
// to call on every SessionStart.
func fileChanged(src, dst string) bool {
	si, err := os.Stat(src)
	if err != nil {
		return false // can't read source — nothing useful to copy
	}
	di, err := os.Stat(dst)
	if err != nil {
		return true // destination missing
	}
	return si.Size() != di.Size() || si.ModTime().After(di.ModTime())
}
