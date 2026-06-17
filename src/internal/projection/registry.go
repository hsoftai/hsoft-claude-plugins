// Package projection is the OS-independent core of sandbox-dlp: the per-exec
// registry that decides, for every file read intercepted by the file-system
// provider (WinFsp on Windows, macFUSE/FSKit on macOS), whether the caller should
// see the RENDERED secret value or the ORIGINAL reference bytes.
//
// The rule is per process and per file:
//
//   - The caller's PID is in the authorized subtree of an active exec, AND the path
//     is one of that exec's declared ref-files → serve the rendered bytes from RAM.
//   - Otherwise → pass through (the provider reads the original from the backing).
//
// The rendered values live ONLY here, in memory, for the duration of one exec; they
// are never written to the backing store, so the real disk only ever holds the
// references. On deregister the bytes are scrubbed. Every uncertain case fails closed
// to pass-through (the original), so a bug can withhold a value but never leak one to
// a process outside the authorized subtree.
//
// This package is pure (no syscalls, no FUSE): the OS-specific provider canonicalizes
// the read path + caller PID and asks Resolve what to do. That keeps the security
// decision fully unit-testable on any platform.
package projection

import (
	"path/filepath"
	"sync"
)

// SubtreeOracle reports whether a process belongs to an exec's authorized subtree.
// Implementations are OS-specific and race-resistant: a Windows Job Object queried
// with IsProcessInJob, or a macOS (pid, pidversion) set fed by ES/proc events. The
// pure core never walks parent PIDs itself (PID reuse is unsafe).
type SubtreeOracle interface {
	// InSubtree reports whether pid is currently a member of the authorized subtree.
	// It must fail closed (return false) on any uncertainty, so the provider serves
	// the original reference rather than a value.
	InSubtree(pid int) bool
}

// Registry holds the currently active exec registrations. It is safe for concurrent
// use: the provider's read handler calls Resolve from many threads while the control
// server registers and deregisters execs.
type Registry struct {
	mu     sync.Mutex
	byExec map[string]*registration
}

type registration struct {
	execID     string
	root       string            // backing project root (clean absolute path)
	mountpoint string            // where the projection is mounted for this exec
	rendered   map[string][]byte // clean absolute ref-file path -> rendered bytes
	oracle     SubtreeOracle
	token      string // one-time token; only its holder may deregister
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{byExec: map[string]*registration{}}
}

// Register activates an exec. rendered maps each declared ref-file's absolute path to
// the bytes the authorized subtree should read; paths are cleaned. The oracle decides
// subtree membership per read; the token gates a later Deregister. An execID already
// present is replaced (its old bytes scrubbed) so a retried registration can't leak
// the previous map.
func (r *Registry) Register(execID, root, mountpoint string, rendered map[string][]byte, oracle SubtreeOracle, token string) {
	clean := make(map[string][]byte, len(rendered))
	for p, b := range rendered {
		clean[filepath.Clean(p)] = b
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.byExec[execID]; ok {
		scrub(old.rendered)
	}
	r.byExec[execID] = &registration{
		execID:     execID,
		root:       filepath.Clean(root),
		mountpoint: filepath.Clean(mountpoint),
		rendered:   clean,
		oracle:     oracle,
		token:      token,
	}
}

// CheckToken reports whether execID is registered with the matching token, without
// removing it or scrubbing its bytes. The service uses it to authorize a deregister and
// unmount the projection (stopping all readers) BEFORE the scrubbing Deregister runs, so
// no read can race a half-scrubbed buffer.
func (r *Registry) CheckToken(execID, token string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	reg, ok := r.byExec[execID]
	return ok && reg.token == token
}

// Deregister ends an exec and scrubs its rendered bytes from memory. It is a no-op
// unless the token matches the one given at Register (so only the owning sandbox
// process can tear down its exec). It returns whether an exec was removed.
func (r *Registry) Deregister(execID, token string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	reg, ok := r.byExec[execID]
	if !ok || reg.token != token {
		return false
	}
	scrub(reg.rendered)
	delete(r.byExec, execID)
	return true
}

// Resolve is the per-read decision. Given the absolute path the provider was asked to
// read and the requesting process's PID, it returns the rendered bytes to serve when
// (and only when) the path is a declared ref-file of some active exec AND the caller
// is in that exec's authorized subtree. In every other case serve is false and the
// provider must pass through to the backing (the original reference bytes).
//
// The returned slice aliases the registry's buffer; callers must not mutate it (the
// provider only ever slices it for offset/length). It stays valid until the exec is
// deregistered.
func (r *Registry) Resolve(path string, callerPID int) (content []byte, serve bool) {
	clean := filepath.Clean(path)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, reg := range r.byExec {
		b, ok := reg.rendered[clean]
		if !ok {
			continue
		}
		// The path is a declared ref-file for this exec. Serve the rendered bytes only
		// to the authorized subtree; any other caller gets the original (pass-through).
		if reg.oracle != nil && reg.oracle.InSubtree(callerPID) {
			return b, true
		}
		return nil, false
	}
	return nil, false
}

// IsManaged reports whether path is a declared ref-file of some active exec, regardless of
// caller. The provider uses it to REFUSE writes/renames/removes of a rendered file, so the
// secret value can never be persisted to the backing and the on-disk reference file is
// never modified through the mount. It is read-only and does not affect the per-caller
// serve decision in Resolve.
func (r *Registry) IsManaged(path string) bool {
	clean := filepath.Clean(path)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.isManagedLocked(clean)
}

// isManagedLocked reports whether clean (already filepath.Clean'd) is a declared ref-file
// of some active exec. Callers must hold r.mu.
func (r *Registry) isManagedLocked(clean string) bool {
	for _, reg := range r.byExec {
		if _, ok := reg.rendered[clean]; ok {
			return true
		}
	}
	return false
}

// MutateIfUnmanaged runs fn (a destructive filesystem operation on the given backing
// paths) atomically with respect to registration: it holds the registry lock across both
// the managed-file check and fn, so a path cannot become a declared ref-file between the
// check and the operation (the Write/Truncate/Unlink/Rename TOCTOU). If any of paths is
// currently a declared ref-file, fn is NOT run and ok is false (fail-closed: the provider
// returns EACCES); otherwise fn runs under the lock and ok is true. fn must not call back
// into the registry (it would deadlock) and should be a single quick syscall.
func (r *Registry) MutateIfUnmanaged(fn func() error, paths ...string) (err error, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range paths {
		if r.isManagedLocked(filepath.Clean(p)) {
			return nil, false
		}
	}
	return fn(), true
}

// Active reports the number of registered execs (for health/status reporting).
func (r *Registry) Active() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byExec)
}

// scrub zeroes every rendered buffer so secret values do not linger in freed memory.
func scrub(m map[string][]byte) {
	for k, b := range m {
		for i := range b {
			b[i] = 0
		}
		delete(m, k)
	}
}
