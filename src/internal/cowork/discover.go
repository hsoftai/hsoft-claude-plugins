package cowork

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DiscoverSpool returns the VM-side path of the shared `outputs` mount that the
// host writes responses into. The host and the VM see the SAME bind-mounted
// directory under different paths, so there is nothing to translate: the VM simply
// finds its own view.
//
// Order: an explicit hint (if it exists), then the Cowork VM convention
// `/sessions/*/mnt/outputs` (newest first), then CLAUDE_PROJECT_DIR as a fallback.
func DiscoverSpool(hint string) (string, error) {
	if d := strings.TrimSpace(hint); d != "" && isDir(d) {
		return d, nil
	}
	if best := newestDir(vmSpoolGlobs()); best != "" {
		return best, nil
	}
	if d := strings.TrimSpace(os.Getenv("CLAUDE_PROJECT_DIR")); d != "" && isDir(d) {
		return d, nil
	}
	return "", fmt.Errorf("no Cowork outputs spool found (looked under /sessions/*/mnt/outputs)")
}

// vmSpoolGlobs are the candidate glob patterns for the VM view of the shared mount.
func vmSpoolGlobs() []string {
	return []string{
		"/sessions/*/mnt/outputs",
		"/sessions/*/outputs",
	}
}

func newestDir(globs []string) string {
	type cand struct {
		path string
		mod  int64
	}
	var cands []cand
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.IsDir() {
				cands = append(cands, cand{m, fi.ModTime().UnixNano()})
			}
		}
	}
	if len(cands) == 0 {
		return ""
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod > cands[j].mod })
	return cands[0].path
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
