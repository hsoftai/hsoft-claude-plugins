package cowork

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	spoolSubdir = ".sg-cw"
	// maxRefsPerRequest caps how many references a single request may ask for, so a
	// rogue VM process cannot fan out a resolve-storm (Touch ID / rate) in one shot.
	// The sandbox batches every reference found across env + files into one request,
	// so this is generous (still bounded).
	maxRefsPerRequest = 512
	// maxRequestBytes caps the size of a request/response file we will read.
	maxRequestBytes = 1 << 20 // 1 MiB
	pollInterval    = 100 * time.Millisecond
)

// Resolver is the minimal vault capability the host needs (satisfied by
// *vault.Resolver): resolve a single reference to its value.
type Resolver interface {
	ResolveString(s string) (string, []string, error)
}

// request is what the VM writes to the spool. NOTHING here is secret: a public
// key, the references (paths, not values), an exec id, and an HMAC proving the VM
// holds the one-time token (handed over a file descriptor, never on disk).
type request struct {
	ExecID       string   `json:"exec_id"`
	Refs         []string `json:"refs"`
	RecipientPub string   `json:"recipient_pub"` // base64 X25519 public key
	Auth         string   `json:"auth"`          // base64 HMAC(token, exec_id‖recipient_pub)
	Stamp        int64    `json:"stamp"`
}

// response is what the host writes back: a sealed blob (only the VM's in-memory
// private key opens it) plus an Ed25519 signature over the WHOLE envelope.
type response struct {
	ExecID  string `json:"exec_id"`
	Status  string `json:"status"`             // ok | error
	Sealed  string `json:"sealed,omitempty"`   // base64 ephPub||nonce||ciphertext
	HostSig string `json:"host_sig,omitempty"` // base64 Ed25519 over envelopeBytes
	Error   string `json:"error,omitempty"`
}

func reqPath(spool, execID string) string {
	return filepath.Join(spool, spoolSubdir, "req-"+sanitize(execID)+".json")
}
func resPath(spool, execID string) string {
	return filepath.Join(spool, spoolSubdir, "res-"+sanitize(execID)+".json")
}
func hostKeyPath(spool string) string {
	return filepath.Join(spool, spoolSubdir, "host.pub")
}

// ---------- host side ----------

// PublishHostKey writes the host's Ed25519 public key to the spool. NOTE (C1):
// this is INFORMATIONAL only — the VM does NOT trust it as the verification key
// (the real anchor is delivered to the VM via the command line, `--host-pub`). If
// a host.pub already exists with DIFFERENT content, that is a tamper signal (the
// VM can create files in the spool); we refuse to overwrite and report it.
func PublishHostKey(spool string, pub ed25519.PublicKey) error {
	if err := ensureDir(spool); err != nil {
		return err
	}
	want := base64.StdEncoding.EncodeToString(pub)
	if existing, err := readNoFollow(hostKeyPath(spool)); err == nil {
		if strings.TrimSpace(string(existing)) != want {
			return fmt.Errorf("host.pub on spool differs from ours (possible tamper); not a trust anchor")
		}
		return nil
	}
	return writeFileNoFollow(hostKeyPath(spool), []byte(want))
}

// HostOpts configures how the host answers a request.
type HostOpts struct {
	Resolver Resolver
	Signer   *hostSigner
	// Auth returns the one-time token and the per-exec allowed references for an
	// exec id, registered out-of-band by the hook in a HOST-ONLY directory. ok=false
	// (unknown/expired/used exec) => the request is denied. This is the request
	// authentication root (H1) and the least-privilege allowlist at once.
	Auth func(execID string) (token []byte, allowed []string, ok bool)
	// Enforce denies references not present in the per-exec allowed list.
	Enforce bool
	// OnResolve registers each resolved (ref,value) on the host (seen/cache + audit)
	// so a later reappearance in the VM's tool output can be detected/blocked.
	OnResolve func(ref, value string)
	// OnServed is called after a value is delivered for execID, so the caller can
	// retire the one-time token (single-use).
	OnServed func(execID string)
}

// inList reports whether ref is in the per-exec allowlist.
func inList(ref string, list []string) bool {
	for _, a := range list {
		if a == ref {
			return true
		}
	}
	return false
}

// serveRequest reads one request, authenticates it, resolves its (allowed) refs,
// seals the values to the requester's public key, signs the envelope, and writes
// the response. Returns delivered=true only when a real value was sent (so the
// daemon resets its idle timer on genuine work, not on rejected probes — M2).
func serveRequest(spool, execID string, o HostOpts) (delivered bool, err error) {
	data, err := readNoFollow(reqPath(spool, execID))
	if err != nil {
		return false, err // not readable yet — retry later, do not mark done
	}
	var rq request
	if json.Unmarshal(data, &rq) != nil || rq.ExecID != execID {
		return false, writeResponse(spool, errResp(execID, "bad-request"), o.Signer)
	}
	if len(rq.Refs) > maxRefsPerRequest {
		return false, writeResponse(spool, errResp(execID, "too-many-refs"), o.Signer)
	}
	pubBytes, derr := base64.StdEncoding.DecodeString(rq.RecipientPub)
	if derr != nil || len(pubBytes) != x25519PubLen {
		return false, writeResponse(spool, errResp(execID, "bad-pubkey"), o.Signer)
	}

	// H1: authenticate the request with the one-time token bound to (execID, pub).
	var token []byte
	var allowed []string
	ok := false
	if o.Auth != nil {
		token, allowed, ok = o.Auth(execID)
	}
	mac, _ := base64.StdEncoding.DecodeString(rq.Auth)
	if !ok || !verifyRequestMAC(token, execID, pubBytes, mac) {
		return false, writeResponse(spool, errResp(execID, "unauthorized"), o.Signer)
	}

	recipientPub, perr := ecdh.X25519().NewPublicKey(pubBytes)
	if perr != nil {
		return false, writeResponse(spool, errResp(execID, "bad-pubkey"), o.Signer)
	}

	values := make(map[string]string, len(rq.Refs))
	for _, ref := range dedupe(rq.Refs) {
		if o.Enforce && !inList(ref, allowed) {
			return false, writeResponse(spool, errResp(execID, "ref-not-approved"), o.Signer)
		}
		out, vals, rerr := o.Resolver.ResolveString(ref)
		if rerr != nil {
			return false, writeResponse(spool, errResp(execID, "resolve-failed"), o.Signer)
		}
		v := out
		if len(vals) > 0 {
			v = vals[0]
		}
		values[ref] = v
		if o.OnResolve != nil {
			o.OnResolve(ref, v)
		}
	}

	plain, merr := json.Marshal(values)
	if merr != nil {
		return false, writeResponse(spool, errResp(execID, "internal"), o.Signer)
	}
	sealedBlob, serr := seal(recipientPub, plain, []byte(execID))
	// Best-effort wipe of the plaintext map.
	for k := range values {
		values[k] = ""
	}
	if serr != nil {
		return false, writeResponse(spool, errResp(execID, "seal-failed"), o.Signer)
	}
	resp := response{ExecID: execID, Status: "ok", Sealed: base64.StdEncoding.EncodeToString(sealedBlob)}
	if werr := writeResponse(spool, resp, o.Signer); werr != nil {
		return false, werr
	}
	if o.OnServed != nil {
		o.OnServed(execID)
	}
	return true, nil
}

func errResp(execID, msg string) response {
	return response{ExecID: execID, Status: "error", Error: msg}
}

func writeResponse(spool string, r response, signer *hostSigner) error {
	if r.Status == "" {
		if r.Error != "" {
			r.Status = "error"
		} else {
			r.Status = "ok"
		}
	}
	if signer != nil {
		sealed, _ := base64.StdEncoding.DecodeString(r.Sealed)
		r.HostSig = base64.StdEncoding.EncodeToString(
			signer.sign(envelopeBytes(r.ExecID, r.Status, sealed, []byte(r.Error))))
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := ensureDir(spool); err != nil {
		return err
	}
	return writeFileNoFollow(resPath(spool, r.ExecID), data)
}

// ---------- VM side ----------

// Fetch (run in the Cowork VM) resolves refs by asking the host over the spool.
// It generates an ephemeral keypair in memory, proves possession of the one-time
// token via an HMAC bound to its public key, writes the request, waits for the
// host's signed sealed response, verifies the WHOLE envelope, and opens it with
// the in-memory private key. The value exists only in this process's RAM.
//
// token is the one-time secret handed to this process over a file descriptor by
// the hook (never on disk/argv/env). hostPub is the verification key delivered via
// the command line (the trust anchor — NOT read from the spool).
func Fetch(spool, execID string, refs []string, hostPub ed25519.PublicKey, token []byte, timeout time.Duration) (map[string]string, error) {
	if len(hostPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("missing/invalid host public key (command anchor)")
	}
	priv, err := genRecipient()
	if err != nil {
		return nil, err
	}
	if err := ensureDir(spool); err != nil {
		return nil, err
	}
	recipientPub := priv.PublicKey().Bytes()
	rq := request{
		ExecID:       execID,
		Refs:         dedupe(refs),
		RecipientPub: base64.StdEncoding.EncodeToString(recipientPub),
		Auth:         base64.StdEncoding.EncodeToString(requestMAC(token, execID, recipientPub)),
		Stamp:        time.Now().Unix(),
	}
	data, merr := json.Marshal(rq)
	if merr != nil {
		return nil, merr
	}
	if err := writeFileNoFollow(reqPath(spool, execID), data); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		raw, rerr := readNoFollow(resPath(spool, execID))
		if rerr != nil {
			time.Sleep(pollInterval)
			continue
		}
		var rp response
		if json.Unmarshal(raw, &rp) != nil || rp.ExecID != execID {
			time.Sleep(pollInterval)
			continue
		}
		sealed, _ := base64.StdEncoding.DecodeString(rp.Sealed)
		sig, _ := base64.StdEncoding.DecodeString(rp.HostSig)
		// Authenticity: an unsigned/forged/tampered response is IGNORED, not fatal
		// (M3). A planted fake must not be able to abort the exec; keep polling for
		// the genuine host response until the deadline.
		if !verifyHost(hostPub, envelopeBytes(rp.ExecID, rp.Status, sealed, []byte(rp.Error)), sig) {
			time.Sleep(pollInterval)
			continue
		}
		if rp.Error != "" || rp.Status != "ok" {
			return nil, fmt.Errorf("host: %s", firstNonEmpty(rp.Error, rp.Status))
		}
		plain, oerr := open(priv, sealed, []byte(execID))
		if oerr != nil {
			return nil, fmt.Errorf("could not open sealed response: %w", oerr)
		}
		var values map[string]string
		if err := json.Unmarshal(plain, &values); err != nil {
			return nil, err
		}
		return values, nil
	}
	return nil, fmt.Errorf("timed out waiting for the host to resolve (is the secrets-guard host daemon running?)")
}

// ReadHostKey loads the host's published Ed25519 public key from the spool. NOTE:
// this is for DIAGNOSTICS only — it is NOT the verification anchor (see C1). The
// anchor is passed to the VM via the command line.
func ReadHostKey(spool string) (ed25519.PublicKey, error) {
	data, err := readNoFollow(hostKeyPath(spool))
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad host key length")
	}
	return ed25519.PublicKey(b), nil
}

// ---------- helpers ----------

// readNoFollow reads a file WITHOUT following a final-component symlink (M1): the
// VM can create nodes in the shared spool, so it could plant a symlink at a
// request/response path pointing at an arbitrary host file. O_NOFOLLOW makes the
// read fail-closed instead of reading through it. Size is capped.
func readNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	if fi.Size() > maxRequestBytes {
		return nil, fmt.Errorf("file too large: %s", path)
	}
	return io.ReadAll(io.LimitReader(f, maxRequestBytes))
}

func ensureDir(spool string) error {
	if strings.TrimSpace(spool) == "" {
		return fmt.Errorf("empty spool path")
	}
	dir := filepath.Join(spool, spoolSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("spool subdir is a symlink; refusing")
	}
	return nil
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
