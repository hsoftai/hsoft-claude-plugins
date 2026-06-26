// Package cache is a per-session, in-memory secret-value cache. A small daemon
// (one process per Claude session) holds the resolved secret VALUES in memory
// only — never on disk — behind a 0600 unix socket. The hooks add a value once,
// at resolution time (when the developer has unlocked the vault), and then query
// the cache to detect/redact that value if it reappears in any later tool I/O.
// This avoids re-resolving the vault on every check (no repeated Touch ID) and,
// crucially, does not fail open when the vault is later locked.
//
// Values live only in the daemon's RAM and vanish when the session ends (a
// SessionEnd shutdown, or a 30-minute idle timeout). Nothing here touches disk.
package cache

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/hsoftai/hsoft-claude-plugins/internal/seen"
)

// minLen mirrors seen.minLen: short secrets (e.g. PINs) are still tracked so they
// can be redacted/blocked rather than leaking into the transcript.
const minLen = 4

// socketDir returns a PRIVATE per-user 0700 directory for the cache socket — not
// bare /tmp. Bare /tmp (sticky 1777) plus a session-derivable socket name let any
// local process pre-bind an impostor daemon that answers `scan` as "clean",
// silently disabling the resolved-value leak backstop. A 0700 dir keyed by uid
// keeps other users out while staying short enough for macOS's ~104-byte unix
// socket path limit.
//
// SECURITY (CTF-9, impostor daemon): keying the dir by uid is not enough on its own.
// On sticky /tmp a co-resident user can pre-create secrets-guard-sock-<victim-uid>
// owned by THEMSELVES (mode 0700); the victim's MkdirAll then no-ops on the existing
// attacker-owned dir, and the attacker can pre-bind the (session-derivable) socket
// path. The victim's listen() sees a "live daemon" and the client's scan talks to
// the IMPOSTOR, which answers `found:false` — silently disabling the leak backstop.
// We therefore verify the dir is exclusively OUR own 0700 dir (seen.VerifyOwned, the
// same guard the reference ledger uses) on every use, and return "" if not. Callers
// treat "" as "cache unavailable" and FAIL CLOSED (the hook falls back to re-resolving
// the recorded references via seen.Contains, which never trusts a foreign process).
func socketDir() string {
	dir := os.Getenv("SG_CACHE_DIR")
	if dir == "" {
		base := "/tmp"
		if runtime.GOOS == "windows" {
			base = os.TempDir()
		}
		dir = filepath.Join(base, fmt.Sprintf("secrets-guard-sock-%d", os.Getuid()))
	}
	_ = os.MkdirAll(dir, 0o700)
	if !seen.VerifyOwned(dir) {
		return "" // missing/hijacked/loose-permissioned — refuse to trust a daemon here
	}
	return dir
}

// sockPath returns the per-session socket path, or "" when the socket directory is
// not safely owned by us (callers must then treat the cache as unavailable).
func sockPath(session string) string {
	dir := socketDir()
	if dir == "" {
		return ""
	}
	h := sha256.Sum256([]byte(session))
	return filepath.Join(dir, "sgc-"+hex.EncodeToString(h[:])[:16]+".sock")
}

type request struct {
	Op     string   `json:"op"`
	Values []string `json:"values,omitempty"`
	Text   string   `json:"text,omitempty"`
	Primed bool     `json:"primed,omitempty"` // an `add` that marks the full vault loaded
}

type response struct {
	OK       bool   `json:"ok"`
	Found    bool   `json:"found,omitempty"`
	Redacted string `json:"redacted,omitempty"`
	Primed   bool   `json:"primed,omitempty"` // (status) whether the full vault was loaded
}

// --- daemon ---

type server struct {
	mu     sync.Mutex
	values []string
	known  map[string]struct{}
	primed bool // the full vault has been loaded into this session's cache at least once
}

// RunDaemon serves the cache for one session until shutdown or idle timeout.
func RunDaemon(session string) error {
	path := sockPath(session)
	if path == "" {
		// Socket dir is not exclusively ours (hijacked / loose-permissioned). Do NOT
		// bind a daemon there — a co-resident impostor could be squatting it. Fail
		// closed: callers fall back to the on-disk reference ledger (seen.Contains).
		return fmt.Errorf("cache socket dir unavailable or not exclusively owned")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	l, err := listen(path)
	if err != nil || l == nil {
		return err // another daemon already owns this session, or bind failed
	}
	defer l.Close()
	defer os.Remove(path)
	_ = os.Chmod(path, 0o600)

	srv := &server{known: map[string]struct{}{}}
	idle := time.AfterFunc(30*time.Minute, func() { l.Close() })

	for {
		conn, err := l.Accept()
		if err != nil {
			return nil
		}
		idle.Reset(30 * time.Minute)
		if srv.handle(conn) {
			return nil // shutdown
		}
	}
}

func listen(path string) (net.Listener, error) {
	if l, err := net.Listen("unix", path); err == nil {
		return l, nil
	}
	// Bind failed: either a live daemon owns it, or a stale socket remains.
	if c, err := net.DialTimeout("unix", path, 300*time.Millisecond); err == nil {
		c.Close()
		return nil, nil // a live daemon already exists
	}
	_ = os.Remove(path)
	return net.Listen("unix", path)
}

func (s *server) handle(conn net.Conn) (shutdown bool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return false
	}
	var rq request
	if json.Unmarshal(line, &rq) != nil {
		return false
	}
	var rp response
	switch rq.Op {
	case "add":
		s.mu.Lock()
		for _, v := range rq.Values {
			if len(v) < minLen {
				continue
			}
			if _, ok := s.known[v]; !ok {
				s.known[v] = struct{}{}
				s.values = append(s.values, v)
			}
		}
		if rq.Primed {
			s.primed = true // the caller loaded the full vault (even if it was empty)
		}
		s.mu.Unlock()
		rp.OK = true
	case "status":
		s.mu.Lock()
		rp.Primed = s.primed
		s.mu.Unlock()
		rp.OK = true
	case "scan":
		s.mu.Lock()
		vals := append([]string(nil), s.values...)
		s.mu.Unlock()
		red, n := seen.Redact(rq.Text, vals)
		rp.OK, rp.Found, rp.Redacted = true, n > 0, red
	case "ping":
		rp.OK = true
	case "shutdown":
		rp.OK = true
		writeResp(conn, rp)
		return true
	}
	writeResp(conn, rp)
	return false
}

func writeResp(conn net.Conn, rp response) {
	b, _ := json.Marshal(rp)
	_, _ = conn.Write(append(b, '\n'))
}

// --- client ---

// Client talks to the per-session cache daemon, spawning it on demand.
type Client struct{}

// New returns a cache Client.
func New() Client { return Client{} }

func roundtrip(session string, rq request, spawnIfDown bool) (response, bool) {
	path := sockPath(session)
	if path == "" {
		// Socket dir not exclusively ours: treat the cache as unavailable so the caller
		// falls back to the on-disk ledger instead of trusting a possible impostor.
		return response{}, false
	}
	conn, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err != nil {
		if !spawnIfDown || !spawnDaemon(session) {
			return response{}, false
		}
		conn, err = net.DialTimeout("unix", path, 500*time.Millisecond)
		if err != nil {
			return response{}, false
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := json.Marshal(rq)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return response{}, false
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return response{}, false
	}
	var rp response
	if json.Unmarshal(line, &rp) != nil {
		return response{}, false
	}
	return rp, true
}

// Detach configures cmd so a spawned child fully outlives the current process
// (new session leader on Unix, new process group on Windows). Exported so other
// daemons in this binary (e.g. the Cowork host daemon) can reuse the same mechanism.
func Detach(cmd *exec.Cmd) { detach(cmd) }

func spawnDaemon(session string) bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	cmd := exec.Command(self, "cache-daemon")
	cmd.Env = append(os.Environ(), "SG_SESSION="+session)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	detach(cmd) // OS-specific: fully detach so the daemon outlives this hook
	if err := cmd.Start(); err != nil {
		return false
	}
	_ = cmd.Process.Release()
	path := sockPath(session)
	for i := 0; i < 40; i++ {
		if c, e := net.DialTimeout("unix", path, 100*time.Millisecond); e == nil {
			c.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// Add caches resolved secret values for the session (spawns the daemon).
func (Client) Add(session string, values []string) {
	if len(values) == 0 {
		return
	}
	roundtrip(session, request{Op: "add", Values: values}, true)
}

// AddPrimed caches values AND marks the session as primed (the full vault has been loaded),
// so callers can avoid reloading it on every hook event. Spawns the daemon; marks primed
// even when values is empty (a genuinely empty vault is still "loaded").
func (Client) AddPrimed(session string, values []string) {
	roundtrip(session, request{Op: "add", Values: values, Primed: true}, true)
}

// Primed reports whether the full vault has been loaded into this session's cache. false
// when the daemon is unreachable (caller should then load + AddPrimed). Does NOT spawn the
// daemon — a missing daemon means "not primed yet".
func (Client) Primed(session string) bool {
	rp, ok := roundtrip(session, request{Op: "status"}, false)
	return ok && rp.Primed
}

// Scan asks the cache whether text contains a cached value and for the redacted
// text. ok is false when the daemon is unreachable (caller should fall back).
func (Client) Scan(session, text string) (found bool, redacted string, ok bool) {
	rp, ok := roundtrip(session, request{Op: "scan", Text: text}, false)
	if !ok {
		return false, text, false
	}
	return rp.Found, rp.Redacted, true
}

// Shutdown stops the session daemon (called on SessionEnd).
func (Client) Shutdown(session string) {
	roundtrip(session, request{Op: "shutdown"}, false)
}
