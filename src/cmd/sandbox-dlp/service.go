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
	"os"
	"sync"
	"time"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// dbg writes a diagnostic line to stderr when SG_DLP_DEBUG is set (never logs secret
// values, only resolution metadata).
func dbg(format string, args ...any) {
	if os.Getenv("SG_DLP_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[dlp] "+format+"\n", args...)
	}
}

// mounter mounts a per-exec projection backed by the real project root. Reads of
// declared ref-files are answered by reg.Resolve (rendered for the subtree, original
// otherwise); every other path passes through to the backing. The real implementation
// uses cgofuse (build tag `sandboxdlp`, requires the driver); without it a stub errors.
type mounter interface {
	Mount(execID, mountpoint, root string, reg *projection.Registry) (unmount func() error, err error)
	// Name reports the backing driver (for status), e.g. "macfuse" or "(none)".
	Name() string
}

// reapInterval is how often the service checks for execs to reap (dead root process or
// expired TTL).
const reapInterval = 30 * time.Second

// execEntry is the live state the service keeps per registered exec, so a reaper can tear
// one down when its owning process dies (e.g. the sandbox CLI was hard-killed and never
// got to deregister) or its TTL lapses — otherwise a stale mount and the secret's rendered
// bytes would linger.
type execEntry struct {
	rootPID  int
	token    string
	deadline time.Time
	cleanup  func() error
}

// Service owns the projection registry and the live per-exec mounts.
type Service struct {
	reg   *projection.Registry
	mnt   mounter
	mu    sync.Mutex
	execs map[string]*execEntry // execID -> live exec
}

func newService(m mounter) *Service {
	s := &Service{reg: projection.New(), mnt: m, execs: map[string]*execEntry{}}
	go s.reapLoop()
	return s
}

// handleRegister activates one exec: it mounts the projection (so reads can be served),
// then registers the rendered map gated by a subtree oracle built from the root PID.
// On mount failure nothing is registered (fail-closed: no value is ever exposed).
func (s *Service) handleRegister(req projection.RegisterRequest) projection.Response {
	if err := req.Validate(); err != nil {
		return projection.Response{Error: err.Error()}
	}
	// Resolve any ref-files the client sent as PATHS ONLY (no pre-rendered content): the
	// value is computed HERE, with the service's own credential, and served only to the
	// subtree — it is never resolved on the client and never returned over the control
	// channel. Files that already carry content (dev/tests) are left as-is. Fail-closed.
	if err := resolveFiles(&req); err != nil {
		return projection.Response{Error: fmt.Sprintf("resolve: %v", err)}
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
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 3600
	}
	entry := &execEntry{
		rootPID:  req.RootPID,
		token:    req.Token,
		deadline: time.Now().Add(time.Duration(ttl) * time.Second),
		cleanup:  cleanup,
	}
	s.mu.Lock()
	// Replace any prior mount for this exec id (tear down the old one).
	if old := s.execs[req.ExecID]; old != nil && old.cleanup != nil {
		_ = old.cleanup()
	}
	s.execs[req.ExecID] = entry
	// Register in s.reg only after the entry is stored, and while still holding s.mu, so a
	// concurrent handleDeregister (or the reaper) that observes the exec in s.reg is
	// guaranteed to find (and run) the corresponding cleanup. Otherwise a teardown racing
	// between Apply and the store would close nothing, leaking the oracle's Job Object
	// handle and the mount goroutine.
	req.Apply(s.reg, oracle)
	s.mu.Unlock()
	return projection.Response{OK: true}
}

// detachLocked removes the exec from the live set and returns its teardown closure and
// token. Callers MUST hold s.mu, and MUST run the returned cleanup + reg.Deregister OUTSIDE
// the lock (unmount drains in-flight reads and can block).
func (s *Service) detachLocked(execID string) (cleanup func() error, token string, ok bool) {
	e := s.execs[execID]
	if e == nil {
		return nil, "", false
	}
	delete(s.execs, execID)
	return e.cleanup, e.token, true
}

// reapLoop periodically tears down execs whose owning process has died or whose TTL has
// lapsed — covering a sandbox CLI that was hard-killed (SIGKILL/taskkill) and never
// deregistered, which would otherwise leave a stale mount and the rendered bytes in RAM.
func (s *Service) reapLoop() {
	for {
		time.Sleep(reapInterval)
		s.reapOnce()
	}
}

func (s *Service) reapOnce() {
	now := time.Now()
	type dead struct {
		id, token string
		cleanup   func() error
	}
	var reap []dead
	s.mu.Lock()
	for id, e := range s.execs {
		if now.After(e.deadline) || !processAlive(e.rootPID) {
			reap = append(reap, dead{id, e.token, e.cleanup})
			delete(s.execs, id)
		}
	}
	s.mu.Unlock()
	// Tear down outside the lock: unmount (drains readers) FIRST, then scrub — same
	// fail-closed ordering as handleDeregister.
	for _, d := range reap {
		if d.cleanup != nil {
			_ = d.cleanup()
		}
		s.reg.Deregister(d.id, d.token)
		dbg("reaped exec %s", d.id)
	}
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
	cleanup, _, _ := s.detachLocked(req.ExecID)
	s.mu.Unlock()
	// Stop the filesystem (and drain in-flight reads) before scrubbing the secret bytes.
	if cleanup != nil {
		_ = cleanup()
	}
	// Now no reader can observe the buffer; scrub it from RAM.
	s.reg.Deregister(req.ExecID, req.Token)
	return projection.Response{OK: true}
}

// resolveFiles renders any ref-file that arrived without pre-rendered content, using the
// service's own vault credential. The client sends only the file PATH (under the backing
// root); the service reads it, resolves its references, and stores the rendered bytes —
// so the plaintext value is produced only inside the service and served solely to the
// authorized subtree. Files that already carry content are untouched (dev/tests).
func resolveFiles(req *projection.RegisterRequest) error {
	need := false
	for i := range req.Files {
		if len(req.Files[i].Content) == 0 {
			need = true
			break
		}
	}
	if !need {
		return nil
	}
	ensureCredential() // provision KSM_CONFIG into this process (Windows); no-op elsewhere
	resolver, err := vault.Select("auto", vault.NewRunner(), "")
	if err != nil {
		return err
	}
	dbg("resolveFiles: provider=%v ksmcfg=%v", func() string {
		if resolver == nil {
			return "nil"
		}
		return resolver.ProviderName()
	}(), os.Getenv("KSM_CONFIG") != "")
	if resolver == nil || resolver.ProviderName() == "none" {
		return fmt.Errorf("no vault credential available in the service")
	}
	for i := range req.Files {
		if len(req.Files[i].Content) > 0 {
			continue
		}
		raw, err := os.ReadFile(req.Files[i].Path)
		if err != nil {
			return fmt.Errorf("read ref-file %q: %w", req.Files[i].Path, err)
		}
		rendered, _, rerr := resolver.ResolveString(string(raw))
		if rerr != nil {
			dbg("resolveFiles: ResolveString error: %v", rerr)
			return rerr
		}
		dbg("resolveFiles: rendered %q changed=%v", req.Files[i].Path, rendered != string(raw))
		req.Files[i].Content = []byte(rendered)
	}
	return nil
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
