// Command sandbox-dlp is the per-user system service that renders vault references
// into real secret values for ONLY the secrets-guard sandbox process subtree, on
// macOS and Windows, via an OS file-system virtualization driver (macFUSE/FSKit,
// WinFsp). The rendered value lives only in this service's RAM for one exec and is
// served per-read to the authorized subtree; every other process reading the file
// sees the original references, and the value never touches disk.
//
// The security decision (which read gets the value) lives in internal/projection and
// is fully unit-tested there. This command wires that registry to (1) an OS-specific
// process-subtree oracle, (2) a FUSE-protocol mounter, and (3) an authenticated local
// control channel the per-user secrets-guard CLI registers each exec on.
package main

import (
	"fmt"
	"sync"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// mounter mounts a per-exec projection backed by the real project root. Reads of
// declared ref-files are answered by reg.Resolve (rendered for the subtree, original
// otherwise); every other path passes through to the backing. The real implementation
// uses cgofuse (build tag `sandboxdlp`, requires the driver); without it a stub errors.
type mounter interface {
	Mount(execID, mountpoint, root string, reg *projection.Registry) (unmount func() error, err error)
	// Name reports the backing driver (for status), e.g. "macfuse" or "(none)".
	Name() string
}

// Service owns the projection registry and the live per-exec mounts.
type Service struct {
	reg    *projection.Registry
	mnt    mounter
	mu     sync.Mutex
	mounts map[string]func() error // execID -> unmount
}

func newService(m mounter) *Service {
	return &Service{reg: projection.New(), mnt: m, mounts: map[string]func() error{}}
}

// handleRegister activates one exec: it mounts the projection (so reads can be served),
// then registers the rendered map gated by a subtree oracle built from the root PID.
// On mount failure nothing is registered (fail-closed: no value is ever exposed).
func (s *Service) handleRegister(req projection.RegisterRequest) projection.Response {
	if err := req.Validate(); err != nil {
		return projection.Response{Error: err.Error()}
	}
	// Build the subtree oracle BEFORE the command is spawned so the root process is
	// already placed in its Job Object (Windows) and the command inherits it on spawn.
	oracle := newSubtreeOracle(req.RootPID)
	unmount, err := s.mnt.Mount(req.ExecID, req.Mountpoint, req.Root, s.reg)
	if err != nil {
		// The oracle may own OS resources (a job handle); release them on mount failure.
		closeOracle(oracle)
		return projection.Response{Error: fmt.Sprintf("mount: %v", err)}
	}
	// Teardown must both unmount and release any oracle-owned OS resources.
	cleanup := func() error {
		err := unmount()
		closeOracle(oracle)
		return err
	}
	s.mu.Lock()
	// Replace any prior mount for this exec id (deregister the old one).
	if old := s.mounts[req.ExecID]; old != nil {
		_ = old()
	}
	s.mounts[req.ExecID] = cleanup
	// Register in s.reg only after the cleanup is stored, and while still holding
	// s.mu, so a concurrent handleDeregister that observes the exec in s.reg is
	// guaranteed to find (and run) the corresponding cleanup. Otherwise a deregister
	// racing between Apply and the store would close nothing, leaking the oracle's
	// Job Object handle and the mount goroutine.
	req.Apply(s.reg, oracle)
	s.mu.Unlock()
	return projection.Response{OK: true}
}

// handleDeregister ends an exec: it tears down the mount FIRST, then scrubs the rendered
// bytes from RAM (registry). Unmount stops the FUSE handlers and waits for in-flight reads
// to drain, so by the time the scrub runs no Read can be mid-copy of the buffer. Scrubbing
// before unmount would let a racing read copy out half-zeroed bytes (neither the value nor
// the reference); doing it after keeps the teardown fail-closed.
func (s *Service) handleDeregister(req projection.DeregisterRequest) projection.Response {
	// Acquire s.mu before r.mu (the registry methods take r.mu) to match handleRegister's
	// ordering (it calls req.Apply → reg.Register while holding s.mu). Reversing the order
	// here would let a register and deregister race into a lock-ordering deadlock.
	s.mu.Lock()
	// Authorize without removing/scrubbing yet: a bad token must leave the exec fully
	// intact (still mounted, still serving).
	if !s.reg.CheckToken(req.ExecID, req.Token) {
		s.mu.Unlock()
		return projection.Response{Error: "unknown exec or bad token"}
	}
	unmount := s.mounts[req.ExecID]
	delete(s.mounts, req.ExecID)
	s.mu.Unlock()
	// Stop the filesystem (and drain in-flight reads) before scrubbing the secret bytes.
	if unmount != nil {
		_ = unmount()
	}
	// Now no reader can observe the buffer; scrub it from RAM.
	s.reg.Deregister(req.ExecID, req.Token)
	return projection.Response{OK: true}
}

// closeOracle releases any OS resources an oracle owns (e.g. the Windows Job Object
// handle). Oracles that hold no resources (the darwin oracle) don't implement Close, so
// this is a no-op for them.
func closeOracle(oracle projection.SubtreeOracle) {
	if c, ok := oracle.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// activeExecs reports how many execs are currently projected (for status).
func (s *Service) activeExecs() int { return s.reg.Active() }

// dispatchControl applies one control request to the service. It is transport-agnostic,
// shared by the unix-socket (macOS) and named-pipe (Windows) servers.
func dispatchControl(s *Service, req projection.ControlRequest) projection.Response {
	switch req.Op {
	case projection.OpRegister:
		if req.Register == nil {
			return projection.Response{Error: "missing register payload"}
		}
		return s.handleRegister(*req.Register)
	case projection.OpDeregister:
		if req.Deregister == nil {
			return projection.Response{Error: "missing deregister payload"}
		}
		return s.handleDeregister(*req.Deregister)
	case projection.OpStatus:
		return projection.Response{OK: true, Active: s.activeExecs(), Driver: s.mnt.Name()}
	default:
		return projection.Response{Error: "unknown op"}
	}
}
