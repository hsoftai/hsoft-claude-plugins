package cowork

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// NewExecID returns a fresh hex exec id (filesystem-safe, non-secret).
func NewExecID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// writeSpoolFile writes data atomically WITHOUT following a symlink: the VM can
// create (not delete) files in the shared spool, so it could pre-plant the temp
// path as a symlink to an arbitrary host file; O_EXCL|O_NOFOLLOW (after removing
// any planted node) makes the host write fail-closed instead of writing through it.
func writeFileNoFollow(final string, data []byte) error {
	tmp := final + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// HostSigner is the opaque host signing identity (Ed25519). Created once per host
// daemon; its public half is published to the spool for the VM to verify.
type HostSigner = hostSigner

// NewHost creates a host signing identity and returns it with its public key.
func NewHost() (*HostSigner, []byte, error) {
	s, err := newHostSigner()
	if err != nil {
		return nil, nil, err
	}
	return s, s.pub, nil
}

// NewHostFromSeed reconstructs the host signing identity from a persisted 32-byte
// Ed25519 seed, so the daemon (which signs) and the hook (which embeds the public
// anchor in the command) share ONE identity across processes.
func NewHostFromSeed(seed []byte) (*HostSigner, []byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("bad host seed length %d", len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &hostSigner{priv: priv, pub: pub}, pub, nil
}

// Seed returns the 32-byte Ed25519 seed for persistence (host-only storage).
func (h *hostSigner) Seed() []byte { return h.priv.Seed() }

// Public returns the host's Ed25519 public key.
func (h *hostSigner) Public() ed25519.PublicKey { return h.pub }

// maxServedExecs bounds the done set so a flood of distinct exec ids cannot grow
// host memory without limit (M2). Reaching it stops the daemon (a fresh session
// gets a fresh daemon); far above any real session's command count.
const maxServedExecs = 4096

// Watch runs the host-side daemon loop: it polls one spool directory for incoming
// request files and answers each exactly once. Returns when stop is closed or the
// idle timeout elapses. The plaintext value lives only in this process's memory.
//
// The idle timer is reset ONLY when a genuine value is delivered (M2): rejected
// probes (bad auth, unapproved refs, malformed) do NOT keep the daemon alive, so a
// rogue VM process cannot hold the host's vault unlocked by spamming junk requests.
func Watch(spool string, o HostOpts, idle time.Duration, stop <-chan struct{}) error {
	if err := ensureDir(spool); err != nil {
		return err
	}
	if o.Signer != nil {
		if err := PublishHostKey(spool, o.Signer.pub); err != nil {
			// Informational only (the anchor is the command line). A mismatch is a
			// tamper signal worth surfacing, but never fatal.
			fmt.Fprintln(os.Stderr, "secrets-guard cw-host:", err)
		}
	}
	done := map[string]bool{}
	deadline := time.Now().Add(idle)
	for time.Now().Before(deadline) {
		select {
		case <-stop:
			return nil
		default:
		}
		matches, _ := filepath.Glob(filepath.Join(spool, spoolSubdir, "req-*.json"))
		for _, m := range matches {
			base := filepath.Base(m)
			if done[base] || strings.HasSuffix(m, ".tmp") {
				continue
			}
			execID := strings.TrimSuffix(strings.TrimPrefix(base, "req-"), ".json")
			delivered, err := serveRequest(spool, execID, o)
			if err != nil {
				continue // not yet readable / transient — retry next tick
			}
			done[base] = true // a response (ok or error) was written; never re-answer
			if len(done) >= maxServedExecs {
				return nil
			}
			if delivered {
				deadline = time.Now().Add(idle)
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil
}
