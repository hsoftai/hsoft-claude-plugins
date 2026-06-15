package cowork

import (
	"crypto/rand"
	"encoding/hex"
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

// Watch runs the host-side daemon loop: it polls one spool directory for incoming
// request files and answers each exactly once. Returns when stop is closed or the
// idle timeout elapses. The plaintext value lives only in this process's memory.
func Watch(spool string, o HostOpts, idle time.Duration, stop <-chan struct{}) error {
	if err := ensureDir(spool); err != nil {
		return err
	}
	if o.Signer != nil {
		_ = PublishHostKey(spool, o.Signer.pub)
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
			if serveRequest(spool, execID, o) == nil {
				done[base] = true
				deadline = time.Now().Add(idle)
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil
}
