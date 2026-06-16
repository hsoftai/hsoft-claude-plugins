//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// subtreeOracle (Windows MVP) authorizes a read iff the caller's process-ancestry chain
// reaches the registered root PID. The chain is built from a kernel process snapshot
// (CreateToolhelp32Snapshot), so it reflects the real parent relationships.
//
// Residual (documented): like the macOS MVP, ancestry-walk has a PID-reuse window. The
// hardened path on Windows is to place the spawned command in a Job Object and answer
// membership with IsProcessInJob (race-free, kernel-maintained); this snapshot walk is
// the driver-free MVP used to validate the end-to-end projection first. It fails closed
// (returns false → the provider serves the original reference) on any snapshot error.
type subtreeOracle struct {
	root int
}

func newSubtreeOracle(rootPID int) projection.SubtreeOracle { return subtreeOracle{root: rootPID} }

// InSubtree reports whether pid descends from (or is) the exec's root PID.
func (o subtreeOracle) InSubtree(pid int) bool {
	if o.root <= 0 || pid <= 0 {
		return false
	}
	parents, err := parentMap()
	if err != nil {
		return false // fail closed
	}
	cur := uint32(pid)
	root := uint32(o.root)
	for i := 0; i < 1024; i++ {
		if cur == root {
			return true
		}
		ppid, ok := parents[cur]
		if !ok || ppid == 0 || ppid == cur {
			return false
		}
		cur = ppid
	}
	return false
}

// parentMap snapshots all live processes and returns a pid -> parent-pid map.
func parentMap() (map[uint32]uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return nil, err
	}
	m := make(map[uint32]uint32, 256)
	for {
		m[e.ProcessID] = e.ParentProcessID
		if err := windows.Process32Next(snap, &e); err != nil {
			break // ERROR_NO_MORE_FILES
		}
	}
	return m, nil
}
