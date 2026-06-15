package cowork

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const spoolSubdir = ".sg-cw"

// Resolver is the minimal vault capability the host needs (satisfied by
// *vault.Resolver): resolve a single reference to its value.
type Resolver interface {
	ResolveString(s string) (string, []string, error)
}

// request is what the VM writes to the spool. NOTHING here is secret: a public
// key, the references (paths, not values) and an exec id.
type request struct {
	ExecID       string   `json:"exec_id"`
	Refs         []string `json:"refs"`
	RecipientPub string   `json:"recipient_pub"` // base64 X25519 public key
	Stamp        int64    `json:"stamp"`
}

// response is what the host writes back: a sealed blob (only the VM's in-memory
// private key opens it) plus an Ed25519 signature for authenticity.
type response struct {
	ExecID  string `json:"exec_id"`
	Sealed  string `json:"sealed,omitempty"`   // base64 ephPub||nonce||ciphertext
	HostSig string `json:"host_sig,omitempty"` // base64 Ed25519 over exec_id||sealed
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

// PublishHostKey writes the host's Ed25519 public key to the spool so the VM can
// verify response authenticity. The key is public — safe on the shared disk.
func PublishHostKey(spool string, pub ed25519.PublicKey) error {
	if err := ensureDir(spool); err != nil {
		return err
	}
	return writeFileNoFollow(hostKeyPath(spool), []byte(base64.StdEncoding.EncodeToString(pub)))
}

// HostOpts configures how the host answers a request.
type HostOpts struct {
	Resolver  Resolver
	Signer    *hostSigner
	Allowed   func(ref string) bool   // nil => allow all
	Enforce   bool                    // deny refs not in the allowlist
	OnResolve func(ref, value string) // register value (seen/cache) + audit
}

// serveRequest reads one request, resolves its refs, seals the values to the
// requester's public key, signs, and writes the response. The plaintext value
// exists only in this host process's memory and the sealed (recipient-only) blob.
func serveRequest(spool, execID string, o HostOpts) error {
	var rq request
	data, err := os.ReadFile(reqPath(spool, execID))
	if err != nil {
		return err
	}
	if json.Unmarshal(data, &rq) != nil || rq.ExecID != execID {
		return fmt.Errorf("bad request")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(rq.RecipientPub)
	if err != nil {
		return writeResponse(spool, response{ExecID: execID, Error: "bad-pubkey"}, o.Signer)
	}
	recipientPub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return writeResponse(spool, response{ExecID: execID, Error: "bad-pubkey"}, o.Signer)
	}

	values := make(map[string]string, len(rq.Refs))
	for _, ref := range dedupe(rq.Refs) {
		if o.Allowed != nil && !o.Allowed(ref) && o.Enforce {
			return writeResponse(spool, response{ExecID: execID, Error: "ref-not-approved"}, o.Signer)
		}
		out, vals, rerr := o.Resolver.ResolveString(ref)
		if rerr != nil {
			return writeResponse(spool, response{ExecID: execID, Error: "resolve-failed"}, o.Signer)
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

	plain, err := json.Marshal(values)
	if err != nil {
		return err
	}
	sealedBlob, err := seal(recipientPub, plain, []byte(execID))
	if err != nil {
		return err
	}
	// Wipe the plaintext map's backing as best Go allows.
	for k := range values {
		values[k] = ""
	}
	resp := response{ExecID: execID, Sealed: base64.StdEncoding.EncodeToString(sealedBlob)}
	return writeResponse(spool, resp, o.Signer)
}

func writeResponse(spool string, r response, signer *hostSigner) error {
	if signer != nil {
		r.HostSig = base64.StdEncoding.EncodeToString(signer.sign([]byte(r.ExecID + "|" + r.Sealed)))
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
// It generates an ephemeral keypair in memory, writes a request carrying only its
// public key, waits for the host's signed sealed response, verifies it, and opens
// it with the in-memory private key. The value exists only in this process's RAM.
func Fetch(spool, execID string, refs []string, hostPub ed25519.PublicKey, timeout time.Duration) (map[string]string, error) {
	priv, err := genRecipient()
	if err != nil {
		return nil, err
	}
	if err := ensureDir(spool); err != nil {
		return nil, err
	}
	rq := request{
		ExecID:       execID,
		Refs:         dedupe(refs),
		RecipientPub: base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
		Stamp:        time.Now().Unix(),
	}
	data, _ := json.Marshal(rq)
	if err := writeFileNoFollow(reqPath(spool, execID), data); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		raw, rerr := os.ReadFile(resPath(spool, execID))
		if rerr != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		var rp response
		if json.Unmarshal(raw, &rp) != nil || rp.ExecID != execID {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// Authenticity: reject a forged/tampered response before doing anything.
		sig, _ := base64.StdEncoding.DecodeString(rp.HostSig)
		if !verifyHost(hostPub, []byte(rp.ExecID+"|"+rp.Sealed), sig) {
			return nil, fmt.Errorf("host response signature invalid (possible forgery)")
		}
		if rp.Error != "" {
			return nil, fmt.Errorf("host: %s", rp.Error)
		}
		blob, derr := base64.StdEncoding.DecodeString(rp.Sealed)
		if derr != nil {
			return nil, derr
		}
		plain, oerr := open(priv, blob, []byte(execID))
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

// ReadHostKey loads the host's published Ed25519 public key from the spool.
func ReadHostKey(spool string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(hostKeyPath(spool))
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

func ensureDir(spool string) error {
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
