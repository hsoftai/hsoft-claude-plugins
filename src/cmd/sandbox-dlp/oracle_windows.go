//go:build windows

package main

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// IsProcessInJob is not wrapped by x/sys/windows, so bind it from kernel32 directly.
var (
	modkernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procIsProcessInJob = modkernel32.NewProc("IsProcessInJob")
)

// isProcessInJob reports whether process is a member of job, via kernel32!IsProcessInJob.
func isProcessInJob(process, job windows.Handle) (bool, error) {
	var result int32 // BOOL
	r1, _, e1 := procIsProcessInJob.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&result)))
	if r1 == 0 {
		return false, e1 // e1 is the GetLastError errno when the call fails
	}
	return result != 0, nil
}

// subtreeOracle authorizes a read iff the caller belongs to the exec's process subtree.
//
// Primary mechanism — a Job Object (race-free, no PID-reuse window): at registration the
// service creates a job and assigns the root process (secrets-guard) to it. Because the
// command secrets-guard spawns is created AFTER the assignment, it and all its descendants
// inherit the job automatically. Membership is then answered by IsProcessInJob, which the
// kernel maintains, so a recycled PID can never be mistaken for a subtree member.
//
// Fallback — if the job cannot be created/assigned (e.g. a policy that blocks nesting),
// the oracle degrades to the original ancestry walk (CreateToolhelp32Snapshot). That walk
// has a PID-reuse window but keeps the feature working; both paths fail closed (return
// false → the provider serves the original reference) on any error.
type subtreeOracle struct {
	root int
	mu   sync.Mutex     // guards job against concurrent Close (deregister) and InSubtree (FUSE reads)
	job  windows.Handle // 0 when the job path is unavailable; then the ancestry walk is used
}

// newSubtreeOracle builds the oracle and, when possible, places rootPID in a fresh job so
// the about-to-be-spawned command inherits it. The returned oracle owns the job handle and
// must be Closed when the exec ends (the service wires this into deregister).
func newSubtreeOracle(rootPID int) projection.SubtreeOracle {
	o := &subtreeOracle{root: rootPID}
	if job, err := assignToFreshJob(rootPID); err == nil {
		o.job = job
	}
	return o
}

// assignToFreshJob creates a Job Object and assigns the root process to it. Future
// children of the root inherit the job; existing ones (none yet at registration) do not.
func assignToFreshJob(rootPID int) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(rootPID))
	if err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	defer windows.CloseHandle(ph)
	if err := windows.AssignProcessToJobObject(job, ph); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// Close releases the job handle (dissolving the job; member processes are NOT killed,
// since KILL_ON_JOB_CLOSE is not set). It is a no-op on the ancestry-walk fallback.
func (o *subtreeOracle) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.job != 0 {
		h := o.job
		o.job = 0
		return windows.CloseHandle(h)
	}
	return nil
}

// InSubtree reports whether pid is currently in the exec's subtree.
func (o *subtreeOracle) InSubtree(pid int) bool {
	if o.root <= 0 || pid <= 0 {
		return false
	}
	// Hold the lock across the entire use of the job handle so a concurrent Close()
	// (deregister) cannot CloseHandle the job mid-use, which would be a use-after-free
	// and could let the kernel reuse the handle value and misreport membership.
	o.mu.Lock()
	job := o.job
	if job != 0 {
		ph, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			o.mu.Unlock()
			return false // fail closed
		}
		inJob, err := isProcessInJob(ph, job)
		windows.CloseHandle(ph)
		o.mu.Unlock()
		if err != nil {
			return false // fail closed
		}
		return inJob
	}
	o.mu.Unlock()
	return o.ancestryInSubtree(pid)
}

// ancestryInSubtree is the driver-free fallback: it reports whether pid descends from (or
// is) the root PID, using a kernel process snapshot. Residual: a PID-reuse window.
func (o *subtreeOracle) ancestryInSubtree(pid int) bool {
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
