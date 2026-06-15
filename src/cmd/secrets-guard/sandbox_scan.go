package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// File discovery for the sandbox: find the (typically few) files under the working
// directory that contain vault references, so they can be rendered. The scan is
// deliberately scoped to a configurable set of globs (secret-bearing config files),
// not the whole tree, so it stays cheap even in large repos.

const (
	maxScanFiles    = 20000   // cap on entries visited
	maxRefFiles     = 256     // cap on rendered files
	maxScanFileSize = 1 << 20 // 1 MiB: skip larger candidates
	binarySniff     = 8 << 10 // bytes inspected for a NUL (binary) check
)

// refFile is a file under cwd that contains at least one vault reference.
type refFile struct {
	path string   // absolute path
	refs []string // references found in its content
}

// skipDirs are never descended into (large, vendored, or irrelevant trees).
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, "target": true, ".venv": true, "venv": true,
	"__pycache__": true, ".next": true, ".cache": true, ".terraform": true,
}

// defaultGlobs are the base-name patterns scanned by default — the common ways
// applications keep secrets in files.
func defaultGlobs() []string {
	return []string{
		".env", ".env.*", "*.env",
		"*.yaml", "*.yml", "*.json", "*.toml", "*.ini",
		"*.properties", "*.conf", "*.cfg", "*.config",
		"*.tfvars", "*.envrc", ".envrc",
	}
}

// parseGlobs returns the configured globs, or the defaults when unset.
func parseGlobs(cfg string) []string {
	cfg = strings.TrimSpace(cfg)
	if cfg == "" {
		return defaultGlobs()
	}
	var out []string
	for _, g := range strings.Split(cfg, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	if len(out) == 0 {
		return defaultGlobs()
	}
	return out
}

// matchesGlob reports whether base matches any pattern (case-insensitive).
func matchesGlob(base string, globs []string) bool {
	lower := strings.ToLower(base)
	for _, g := range globs {
		if ok, _ := filepath.Match(strings.ToLower(g), lower); ok {
			return true
		}
	}
	return false
}

// scanRefFiles walks root (bounded) and returns the files matching globs that
// contain vault references. truncated is true if a cap was hit (caller should fall
// back to env-only rendering and warn).
func scanRefFiles(root string, globs []string) (files []refFile, truncated bool) {
	visited := 0
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > 24 || len(files) >= maxRefFiles || visited >= maxScanFiles {
			truncated = truncated || len(files) >= maxRefFiles || visited >= maxScanFiles
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if len(files) >= maxRefFiles || visited >= maxScanFiles {
				truncated = true
				return
			}
			name := e.Name()
			child := filepath.Join(dir, name)
			if e.IsDir() {
				if skipDirs[name] {
					continue
				}
				walk(child, depth+1)
				continue
			}
			if !e.Type().IsRegular() {
				continue // symlinks, sockets, devices
			}
			if !matchesGlob(name, globs) {
				continue
			}
			visited++
			if refs := fileRefs(child); len(refs) > 0 {
				files = append(files, refFile{path: child, refs: refs})
			}
		}
	}
	walk(root, 0)
	return files, truncated
}

// fileRefs returns the vault references in a file, or nil if it is too large,
// binary, or unreadable. Content (which holds references, not values) is read into
// memory only transiently.
func fileRefs(path string) []string {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxScanFileSize {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	head := data
	if len(head) > binarySniff {
		head = head[:binarySniff]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return nil // binary
	}
	return unescapedRefs(string(data))
}
