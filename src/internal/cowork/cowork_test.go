package cowork

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeResolver struct{ m map[string]string }

func (f fakeResolver) ResolveString(s string) (string, []string, error) {
	if v, ok := f.m[s]; ok {
		return v, []string{v}, nil
	}
	return s, nil, fmt.Errorf("not found: %s", s)
}

const secret = "S3cr3t-VM-Value-9z7q"

var testToken = []byte("one-time-token-9f3c2a")

// authFor builds an Auth callback that returns a fixed token and allowlist for any
// exec id (the per-exec persistence is the daemon's job; tests fix it).
func authFor(token []byte, allowed ...string) func(string) ([]byte, []string, bool) {
	return func(string) ([]byte, []string, bool) { return token, allowed, true }
}

func startHost(t *testing.T, spool string, opts HostOpts) (chan struct{}, ed25519.PublicKey) {
	t.Helper()
	signer, hostPub, err := NewHost()
	if err != nil {
		t.Fatal(err)
	}
	opts.Signer = signer
	if opts.Auth == nil {
		opts.Auth = authFor(testToken)
	}
	stop := make(chan struct{})
	go func() { _ = Watch(spool, opts, 3*time.Second, stop) }()
	return stop, hostPub
}

// End-to-end: the VM fetches a value over the spool; only ciphertext + public
// keys ever touch disk.
func TestEndToEnd_SealedDelivery(t *testing.T) {
	spool := t.TempDir()
	stop, hostPub := startHost(t, spool, HostOpts{
		Resolver: fakeResolver{m: map[string]string{"op://v/i/p": secret}},
		Auth:     authFor(testToken, "op://v/i/p"),
		Enforce:  true,
	})
	defer close(stop)

	vals, err := Fetch(spool, NewExecID(), []string{"op://v/i/p"}, hostPub, testToken, 3*time.Second)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if vals["op://v/i/p"] != secret {
		t.Fatalf("wrong value: %+v", vals)
	}

	// The plaintext secret must NOT appear in any spool file (only ciphertext).
	_ = filepath.Walk(spool, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, _ := os.ReadFile(p)
		if strings.Contains(string(data), secret) {
			t.Fatalf("plaintext secret leaked into spool file %s", p)
		}
		return nil
	})
}

// A captured response is useless without the VM's (never-transmitted) private key.
func TestCapturedResponse_Useless(t *testing.T) {
	spool := t.TempDir()
	stop, hostPub := startHost(t, spool, HostOpts{
		Resolver: fakeResolver{m: map[string]string{"op://a/b/c": secret}},
		Auth:     authFor(testToken, "op://a/b/c"),
	})
	defer close(stop)

	execID := NewExecID()
	if _, err := Fetch(spool, execID, []string{"op://a/b/c"}, hostPub, testToken, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	// Attacker captures the response blob and tries to open it with a fresh key.
	raw, _ := os.ReadFile(resPath(spool, execID))
	var rp response
	_ = json.Unmarshal(raw, &rp)
	blob, _ := base64.StdEncoding.DecodeString(rp.Sealed)
	attacker, _ := genRecipient()
	if _, err := open(attacker, blob, []byte(execID)); err == nil {
		t.Fatal("a captured sealed response must NOT be openable without the original private key")
	}
}

// H1: a request without the one-time token (or with the wrong token) is rejected.
func TestUnauthorizedRequest_Rejected(t *testing.T) {
	spool := t.TempDir()
	stop, hostPub := startHost(t, spool, HostOpts{
		Resolver: fakeResolver{m: map[string]string{"op://x/y/z": secret}},
		Auth:     authFor(testToken, "op://x/y/z"),
		Enforce:  true,
	})
	defer close(stop)
	_, err := Fetch(spool, NewExecID(), []string{"op://x/y/z"}, hostPub, []byte("WRONG-token"), 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("wrong token must be unauthorized, got %v", err)
	}
}

// M3: a forged/unsigned response (rogue signer) is IGNORED, not accepted and not
// fatal — with no genuine host it simply times out (never returns the garbage).
func TestForgedResponse_IgnoredNotAccepted(t *testing.T) {
	spool := t.TempDir()
	_, realPub := func() (chan struct{}, ed25519.PublicKey) {
		s, _, _ := NewHost()
		return nil, s.pub // a host pub the VM trusts, but NO daemon serving
	}()

	execID := NewExecID()
	rogueSigner, _, _ := NewHost()
	fake := response{ExecID: execID, Status: "ok", Sealed: base64.StdEncoding.EncodeToString([]byte("garbage"))}
	sealed, _ := base64.StdEncoding.DecodeString(fake.Sealed)
	fake.HostSig = base64.StdEncoding.EncodeToString(
		rogueSigner.sign(envelopeBytes(fake.ExecID, fake.Status, sealed, nil)))
	_ = ensureDir(spool)
	data, _ := json.Marshal(fake)
	_ = writeFileNoFollow(resPath(spool, execID), data)

	_, err := Fetch(spool, execID, []string{"op://x/y/z"}, realPub, testToken, 700*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("forged response must be ignored (time out), got %v", err)
	}
}

// M3 + delivery: a planted forgery must not prevent the genuine host response from
// being accepted.
func TestForgedResponse_RealStillWins(t *testing.T) {
	spool := t.TempDir()
	execID := NewExecID()
	// Pre-plant a forgery at the response path before the real host answers.
	rogueSigner, _, _ := NewHost()
	fake := response{ExecID: execID, Status: "ok", Sealed: base64.StdEncoding.EncodeToString([]byte("garbage"))}
	fsealed, _ := base64.StdEncoding.DecodeString(fake.Sealed)
	fake.HostSig = base64.StdEncoding.EncodeToString(rogueSigner.sign(envelopeBytes(fake.ExecID, fake.Status, fsealed, nil)))
	_ = ensureDir(spool)
	fd, _ := json.Marshal(fake)
	_ = writeFileNoFollow(resPath(spool, execID), fd)

	stop, hostPub := startHost(t, spool, HostOpts{
		Resolver: fakeResolver{m: map[string]string{"op://x/y/z": secret}},
		Auth:     authFor(testToken, "op://x/y/z"),
		Enforce:  true,
	})
	defer close(stop)

	vals, err := Fetch(spool, execID, []string{"op://x/y/z"}, hostPub, testToken, 3*time.Second)
	if err != nil {
		t.Fatalf("genuine response must win over a planted forgery: %v", err)
	}
	if vals["op://x/y/z"] != secret {
		t.Fatalf("wrong value: %+v", vals)
	}
}

// enforce: a reference the host did not approve for this exec is denied.
func TestEnforceAllowlist(t *testing.T) {
	spool := t.TempDir()
	stop, hostPub := startHost(t, spool, HostOpts{
		Resolver: fakeResolver{m: map[string]string{"op://x/y/z": secret}},
		Auth:     authFor(testToken), // empty allowlist
		Enforce:  true,
	})
	defer close(stop)
	_, err := Fetch(spool, NewExecID(), []string{"op://x/y/z"}, hostPub, testToken, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "ref-not-approved") {
		t.Fatalf("enforce should deny, got %v", err)
	}
}

// H2: tampering the response error/status after signing is detected (the signature
// covers the WHOLE envelope, not just the sealed blob).
func TestEnvelopeTamper_Detected(t *testing.T) {
	spool := t.TempDir()
	signer, hostPub, _ := NewHost()
	execID := "exec-h2"
	// A genuine OK response, correctly signed.
	recipient, _ := genRecipient()
	blob, _ := seal(recipient.PublicKey(), []byte(`{"op://a/b":"`+secret+`"}`), []byte(execID))
	r := response{ExecID: execID, Status: "ok", Sealed: base64.StdEncoding.EncodeToString(blob)}
	r.HostSig = base64.StdEncoding.EncodeToString(signer.sign(envelopeBytes(r.ExecID, r.Status, blob, nil)))
	// Attacker flips it to an error to abort the exec, keeping the old signature.
	r.Status, r.Error, r.Sealed = "error", "resolve-failed", ""
	_ = ensureDir(spool)
	data, _ := json.Marshal(r)
	_ = writeFileNoFollow(resPath(spool, execID), data)

	_, err := Fetch(spool, execID, []string{"op://a/b"}, hostPub, testToken, 600*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("tampered envelope must be ignored (time out), got %v", err)
	}
}

// Tampering with the sealed ciphertext is detected (AEAD) even with a valid sig.
func TestTamperedCiphertext_Detected(t *testing.T) {
	recipient, _ := genRecipient()
	blob, err := seal(recipient.PublicKey(), []byte(`{"op://a/b":"`+secret+`"}`), []byte("exec1"))
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0xff // flip a ciphertext byte
	if _, err := open(recipient, blob, []byte("exec1")); err == nil {
		t.Fatal("tampered ciphertext must fail to open")
	}
	// Wrong AAD (replay into another exec) is also rejected.
	good, _ := seal(recipient.PublicKey(), []byte("hi-there"), []byte("execA"))
	if _, err := open(recipient, good, []byte("execB")); err == nil {
		t.Fatal("AAD mismatch (exec rebind) must fail")
	}
}
