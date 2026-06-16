//go:build darwin

package main

import (
	"golang.org/x/sys/unix"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// subtreeOracle (macOS MVP) authorizes a read iff the caller's process-ancestry chain
// reaches the registered root PID — the process the sandbox spawned for this exec. The
// chain is read from the kernel via sysctl(kern.proc.pid), so it reflects the real
// parent relationships, not anything the caller can forge in its own address space.
//
// Residual (documented): ancestry-walk has a PID-reuse window — if the root PID (or an
// intermediate) dies and its number is recycled into an unrelated process before a
// read, that read could be misattributed. The hardened path is an EndpointSecurity
// fork/exec/exit feed maintaining a (pid, pidversion) set; this oracle is the
// driver-free MVP used to validate the end-to-end projection first. It fails closed
// (returns false → the provider serves the original reference) on any sysctl error.
type subtreeOracle struct {
	root int
}

func newSubtreeOracle(rootPID int) projection.SubtreeOracle { return subtreeOracle{root: rootPID} }

// InSubtree reports whether pid descends from (or is) the exec's root PID.
func (o subtreeOracle) InSubtree(pid int) bool {
	if o.root <= 0 || pid <= 0 {
		return false
	}
	cur := pid
	// Bound the climb so a pathological/cyclic chain can never spin.
	for i := 0; i < 64; i++ {
		if cur == o.root {
			return true
		}
		if cur <= 1 { // reached launchd (pid 1) without hitting root
			return false
		}
		ppid, err := parentPID(cur)
		if err != nil || ppid == cur || ppid <= 0 {
			return false // fail closed
		}
		cur = ppid
	}
	return false
}

// parentPID returns the parent PID of pid via sysctl(kern.proc.pid).
func parentPID(pid int) (int, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	return int(kp.Eproc.Ppid), nil
}
