//go:build !linux

package main

import (
	"os"
	"path/filepath"
)

// renderFiles (macOS/Windows) renders each ref-file IN PLACE — there are no mount
// namespaces here, so the only way an app reading a config file by path sees the
// real value is for the real file to contain it during the command. It returns a
// restore() that rewrites the originals (the references) afterward. A recovery
// journal of the originals is written BEFORE any value touches disk, so a hard kill
// is recoverable (SessionStart restores it). The value is on the real file only for
// the command's duration, then reverted.
//
// (On Linux the sibling build uses a private bind-mount instead, so the value never
// touches the real disk at all.)
func renderFiles(files []refFile, values map[string]string) (func(), error) {
	type item struct {
		path, orig, rendered string
	}
	var items []item
	var entries []journalEntry
	for _, f := range files {
		p, err := filepath.Abs(f.path)
		if err != nil {
			continue
		}
		orig, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rendered := renderRefs(string(orig), values)
		if rendered == string(orig) {
			continue // no resolvable reference in this file right now
		}
		items = append(items, item{p, string(orig), rendered})
		entries = append(entries, journalEntry{Path: p, Original: string(orig)})
	}
	if len(items) == 0 {
		return func() {}, nil
	}

	// Journal the originals FIRST (recoverable on crash), then write the values.
	jp := newJournal(entries)
	for _, it := range items {
		_ = os.WriteFile(it.path, []byte(it.rendered), 0o600) // truncate-write keeps perms
	}

	restore := func() {
		for _, it := range items {
			if cur, err := os.ReadFile(it.path); err == nil && string(cur) == it.orig {
				continue
			}
			_ = os.WriteFile(it.path, []byte(it.orig), 0o600)
		}
		removeJournal(jp)
	}
	return restore, nil
}
