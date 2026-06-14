package broker

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Bootstrap is the control-plane handshake the host writes to the shared spool
// (the `outputs` mount) so the VM client can find and authenticate to the broker.
// It NEVER contains a secret value — only the capability token (a per-session
// HMAC key), the address/plan, and the cert fingerprint to pin.
type Bootstrap struct {
	Session  string `json:"session"`
	Plan     string `json:"plan"`                // "A" (VM dials host) or "B" (host dials VM)
	DialAddr string `json:"dial_addr,omitempty"` // Plan A: VM dials here (host vmnet ip:port)
	Port     int    `json:"port,omitempty"`      // Plan B: VM listens on this port
	TokenB64 string `json:"token_b64"`
	CertFP   string `json:"cert_fp,omitempty"` // Plan A: host listener cert fingerprint to pin
	TTLUnix  int64  `json:"ttl_unix"`
}

// Expired reports whether the bootstrap's TTL has passed.
func (b Bootstrap) Expired() bool { return b.TTLUnix > 0 && time.Now().Unix() > b.TTLUnix }

// Token decodes the capability token.
func (b Bootstrap) Token() []byte {
	t, _ := base64.StdEncoding.DecodeString(b.TokenB64)
	return t
}

// rendezvous is what the VM writes to the spool in Plan B so the host knows where
// to dial and which cert to pin. It also never carries a secret value.
type rendezvous struct {
	Session string `json:"session"`
	Addr    string `json:"addr"`    // VM ip:port the host dials
	CertFP  string `json:"cert_fp"` // VM listener cert fingerprint to pin
	Stamp   int64  `json:"stamp"`
}

const spoolSubdir = "secrets-guard"

// NewToken returns a fresh 32-byte capability token (base64).
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func sessionTag(session string) string {
	h := sha256.Sum256([]byte(session))
	return hex.EncodeToString(h[:])[:16]
}

func bootstrapPath(spool, session string) string {
	return filepath.Join(spool, spoolSubdir, "broker-"+sessionTag(session)+".json")
}

func rendezvousPath(spool, session string) string {
	return filepath.Join(spool, spoolSubdir, "rendezvous-"+sessionTag(session)+".json")
}

// WriteBootstrap atomically publishes the bootstrap to the spool (0600).
func WriteBootstrap(spool string, b Bootstrap) error {
	dir, err := ensureSpoolDir(spool)
	if err != nil {
		return err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	final := filepath.Join(dir, "broker-"+sessionTag(b.Session)+".json")
	return writeSpoolFile(final, data)
}

// ensureSpoolDir creates the spool subdir and refuses if it (the component we
// create) is a symlink — preventing a VM-planted symlinked directory from
// redirecting host writes outside the shared mount.
func ensureSpoolDir(spool string) (string, error) {
	dir := filepath.Join(spool, spoolSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("spool subdir %q is a symlink; refusing", dir)
	}
	return dir, nil
}

// writeSpoolFile writes data to final atomically WITHOUT following a symlink: the
// VM can create (not delete) files in the shared spool, so it could pre-plant the
// temp path as a symlink to an arbitrary host file; O_EXCL|O_NOFOLLOW (after
// removing any planted node) makes the host write fail-closed instead of writing
// through it. The destination is then replaced via rename (which never follows a
// symlinked destination name).
func writeSpoolFile(final string, data []byte) error {
	tmp := final + ".tmp"
	_ = os.Remove(tmp) // drop any VM-planted node at the temp path
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

// ReadBootstrap loads the bootstrap for an explicit session from the spool.
func ReadBootstrap(spool, session string) (Bootstrap, error) {
	return readBootstrapFile(bootstrapPath(spool, session))
}

// RemoveBootstrap deletes the session's bootstrap from the spool (host side, on
// broker exit / SessionEnd). Best-effort.
func RemoveBootstrap(spool, session string) { _ = os.Remove(bootstrapPath(spool, session)) }

// RemoveRendezvous deletes the session's Plan B rendezvous file. Best-effort.
func RemoveRendezvous(spool, session string) { _ = os.Remove(rendezvousPath(spool, session)) }

func readBootstrapFile(path string) (Bootstrap, error) {
	var b Bootstrap
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	err = json.Unmarshal(data, &b)
	return b, err
}

// DiscoverBootstrap finds a usable broker bootstrap for the VM client. An exact
// session match is preferred. As a fallback (when the session id is not available
// inside the VM) it accepts a live bootstrap ONLY when exactly one exists across
// the candidate spools — refusing to pick among several, so a planted/rogue or
// cross-session bootstrap cannot be selected by gaming the TTL. Returns the
// bootstrap and the spool it came from.
func DiscoverBootstrap(session string, spools []string) (Bootstrap, string, bool) {
	if session != "" {
		for _, sp := range spools {
			if sp == "" {
				continue
			}
			if b, err := ReadBootstrap(sp, session); err == nil && !b.Expired() {
				return b, sp, true
			}
		}
	}
	// Fallback: only unambiguous when there is a single live bootstrap.
	type hit struct {
		b  Bootstrap
		sp string
	}
	var hits []hit
	for _, sp := range spools {
		if sp == "" {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(sp, spoolSubdir, "broker-*.json"))
		for _, m := range matches {
			if b, err := readBootstrapFile(m); err == nil && !b.Expired() {
				hits = append(hits, hit{b, sp})
			}
		}
	}
	if len(hits) != 1 {
		return Bootstrap{}, "", false // none, or ambiguous → fail closed
	}
	return hits[0].b, hits[0].sp, true
}

// writeRendezvous publishes the VM listener address + cert pin for Plan B.
func writeRendezvous(spool string, r rendezvous) error {
	dir, err := ensureSpoolDir(spool)
	if err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	final := filepath.Join(dir, "rendezvous-"+sessionTag(r.Session)+".json")
	return writeSpoolFile(final, data)
}

func readRendezvous(spool, session string) (rendezvous, error) {
	var r rendezvous
	data, err := os.ReadFile(rendezvousPath(spool, session))
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(data, &r)
	return r, err
}

// CandidateSpools returns the spool directories to search for a bootstrap on the
// VM side, most specific first: an explicit override, the configured value, then
// well-known Cowork mount points. The exact Cowork mount is environment-specific
// and finalized during Cowork testing; extra candidates here are harmless if absent.
func CandidateSpools(configured string) []string {
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		for _, e := range out {
			if e == p {
				return
			}
		}
		out = append(out, p)
	}
	add(strings.TrimSpace(os.Getenv("SG_COWORK_SPOOL")))
	add(strings.TrimSpace(configured))
	add(strings.TrimSpace(os.Getenv("CLAUDE_PLUGIN_OPTION_COWORK_SPOOL")))
	// Well-known / likely Cowork shared-mount locations (VM side).
	for _, c := range []string{"/mnt/outputs", "/mnt/user-data/outputs", "/outputs", "/workspace/outputs"} {
		add(c)
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, "outputs"))
	}
	return out
}

// fmtAddr joins host and port, accepting an empty host (=> all interfaces).
func fmtAddr(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}
