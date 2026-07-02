package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
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
	return installFrom(src, dir, quiet, false)
}

// installFrom copies the binary at src into the user bin dir (dir, or the platform
// default when empty) and ensures that dir is on the user PATH. It self-heals a
// dirty target: it cleans leftover displaced/temp binaries first, and when the
// destination is busy (a running CLI holds the old image locked — common on
// Windows, where a loaded executable cannot be overwritten in place) it displaces
// the stale binary and moves the fresh one into place instead of silently keeping
// the old version. Returns the installed binary's path.
//
// When force is true the copy happens even if the size/mtime heuristic says the
// destination is unchanged — used by the explicit `install` command, where the
// source has been version-checked and two builds of adjacent versions can share
// an identical size (only the embedded version string differs), which the cheap
// heuristic would otherwise miss.
func installFrom(src, dir string, quiet, force bool) (string, error) {
	if dir == "" {
		dir = installTargetDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, installBinName())

	// Best-effort cleanup of any leftover displaced/temp binaries from a previous
	// busy replace (see below). They are no longer referenced once this returns.
	cleanupDisplaced(dir)

	if force || fileChanged(src, dst) {
		tmp := dst + ".tmp"
		if err := copyFile(src, tmp, 0o755); err != nil {
			return dst, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			// The destination is likely busy: a running CLI (this process itself, or
			// another session's) holds the loaded image and Windows refuses to
			// overwrite it in place. Windows DOES allow renaming a running executable,
			// so displace the stale binary and move the fresh one into its place — the
			// next process launch picks up the new version instead of silently keeping
			// the old one (which caused `doctor` to report a version behind the plugin).
			displaced := dst + ".old"
			_ = os.Remove(displaced)
			if renErr := os.Rename(dst, displaced); renErr == nil {
				if err2 := os.Rename(tmp, dst); err2 != nil {
					// Couldn't put the new one in place; restore the old and keep it.
					_ = os.Rename(displaced, dst)
					os.Remove(tmp)
				}
				// The displaced copy may still be locked by the running process; it is
				// removed on the next install via cleanupDisplaced.
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

// cleanupDisplaced removes the `<bin>.old` displaced binary and any `<bin>.tmp`
// left behind when a prior install replaced a busy (locked) executable or was
// interrupted mid-copy. Best-effort: a file still locked by a running process
// fails to delete silently and is retried on the next install.
func cleanupDisplaced(dir string) {
	base := filepath.Join(dir, installBinName())
	os.Remove(base + ".old")
	os.Remove(base + ".tmp")
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

// freshestInstallSource returns the newest secrets-guard binary available to
// install into the user's PATH, and the version it is upgrading TO when that
// source is not the running executable. It considers the running binary and any
// plugin-bundled binaries (the plugin ships the authoritative build). This is why
// a STALE user-PATH CLI running `secrets-guard install` can still upgrade itself:
// instead of copying its own old version back over itself, it sources the newer
// binary from the plugin bundle. A locally-built `dev` binary is never downgraded.
func freshestInstallSource() (src string, upgradeTo string) {
	self, err := os.Executable()
	if err == nil {
		if r, e := filepath.EvalSymlinks(self); e == nil {
			self = r
		}
	}
	best, bestVer := self, version // `version` is compiled into THIS running binary
	for _, cand := range candidateBundleBinaries() {
		if sameFile(cand, self) {
			continue
		}
		cv := binaryVersion(cand)
		if cv == "" {
			continue
		}
		if compareVersions(cv, bestVer) > 0 {
			best, bestVer = cand, cv
		}
	}
	if best != self {
		return best, bestVer
	}
	return self, ""
}

// candidateBundleBinaries returns paths to plugin-bundled secrets-guard binaries
// for THIS platform, discovered from CLAUDE_PLUGIN_ROOT and the user's Claude
// plugins directories. These are the authoritative builds shipped with the plugin.
func candidateBundleBinaries() []string {
	asset := platformAssetName()
	var out []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		if _, err := os.Stat(p); err != nil {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if root := os.Getenv("CLAUDE_PLUGIN_ROOT"); root != "" {
		add(filepath.Join(root, "bin", asset))
	}
	for _, base := range pluginSearchRoots() {
		for _, p := range walkForAsset(base, "secrets-guard", asset, 6) {
			add(p)
		}
	}
	return out
}

// pluginSearchRoots returns the directories under which Claude Code stores plugins.
func pluginSearchRoots() []string {
	var roots []string
	if cfg := os.Getenv("CLAUDE_CONFIG_DIR"); cfg != "" {
		roots = append(roots, filepath.Join(cfg, "plugins"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, filepath.Join(home, ".claude", "plugins"))
	}
	return roots
}

// walkForAsset finds files named asset that live in a `bin` directory whose parent
// directory is pluginDir (…/<pluginDir>/bin/<asset>), searching base up to maxDepth
// levels deep. Bounded so it stays cheap regardless of how the marketplace nests.
func walkForAsset(base, pluginDir, asset string, maxDepth int) []string {
	var found []string
	baseDepth := strings.Count(filepath.Clean(base), string(filepath.Separator))
	filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if strings.Count(filepath.Clean(path), string(filepath.Separator))-baseDepth > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != asset {
			return nil
		}
		binDir := filepath.Dir(path)
		if filepath.Base(binDir) == "bin" && filepath.Base(filepath.Dir(binDir)) == pluginDir {
			found = append(found, path)
		}
		return nil
	})
	return found
}

// platformAssetName is the plugin-bundled binary name for this OS/arch, matching
// the assets committed under plugins/secrets-guard/bin (e.g.
// secrets-guard-windows-amd64.exe, secrets-guard-darwin-arm64).
func platformAssetName() string {
	n := "secrets-guard-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		n += ".exe"
	}
	return n
}

// binaryVersion runs `<path> version` and returns the reported version string
// (e.g. "0.8.4"), or "" if it can't be determined. Time-bounded so a wedged
// binary never hangs the installer.
func binaryVersion(path string) string {
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// compareVersions compares two dotted version strings numerically. An empty or
// "dev" version sorts HIGHEST, so a locally-built binary is never auto-downgraded
// to a released bundle. Returns -1, 0 or 1.
func compareVersions(a, b string) int {
	ka, kb := versionKey(a), versionKey(b)
	n := len(ka)
	if len(kb) > n {
		n = len(kb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(ka) {
			x = ka[i]
		}
		if i < len(kb) {
			y = kb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionKey(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" || v == "dev" {
		return []int{1 << 30} // unknown/dev sorts highest
	}
	parts := strings.Split(v, ".")
	key := make([]int, 0, len(parts))
	for _, p := range parts {
		num := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				break // stop at a pre-release suffix (e.g. "1-rc")
			}
			num = num*10 + int(c-'0')
		}
		key = append(key, num)
	}
	return key
}

// sameFile reports whether a and b are the same file on disk (following the OS's
// identity, not just the textual path).
func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}
