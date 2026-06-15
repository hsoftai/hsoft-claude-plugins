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

func startHost(t *testing.T, spool string, opts HostOpts) (chan struct{}, ed25519.PublicKey) {
	t.Helper()
	signer, hostPub, err := NewHost()
	if err != nil {
		t.Fatal(err)
	}
	opts.Signer = signer
	stop := make(chan struct{})
	go func() { _ = Watch(spool, opts, 3*time.Second, stop) }()
	return stop, hostPub
}

// End-to-end: the VM fetches a value over the spool; only ciphertext + public
// keys ever touch disk.
func TestEndToEnd_SealedDelivery(t *testing.T) {
	spool := t.TempDir()
	stop, hostPub := startHost(t, spool, HostOpts{Resolver: fakeResolver{m: map[string]string{"op://v/i/p": secret}}})
	defer close(stop)

	vals, err := Fetch(spool, NewExecID(), []string{"op://v/i/p"}, hostPub, 3*time.Second)
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
	stop, hostPub := startHost(t, spool, HostOpts{Resolver: fakeResolver{m: map[string]string{"op://a/b/c": secret}}})
	defer close(stop)

	execID := NewExecID()
	if _, err := Fetch(spool, execID, []string{"op://a/b/c"}, hostPub, 3*time.Second); err != nil {
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

// A forged/tampered response (bad host signature) is rejected before decryption.
func TestForgedResponse_Rejected(t *testing.T) {
	spool := t.TempDir()
	stop, hostPub := startHost(t, spool, HostOpts{Resolver: fakeResolver{m: map[string]string{"op://x/y/z": secret}}})
	defer close(stop)

	// VM writes a request; before the host answers, an attacker plants a fake
	// response with a signature from a DIFFERENT host key.
	execID := NewExecID()
	rogueSigner, _, _ := NewHost()
	fake := response{ExecID: execID, Sealed: base64.StdEncoding.EncodeToString([]byte("garbage"))}
	fake.HostSig = base64.StdEncoding.EncodeToString(rogueSigner.sign([]byte(fake.ExecID + "|" + fake.Sealed)))
	_ = ensureDir(spool)
	data, _ := json.Marshal(fake)
	_ = writeFileNoFollow(resPath(spool, execID), data)

	// Fetch must reject the forged response (signature invalid against hostPub).
	_, err := Fetch(spool, execID, []string{"op://x/y/z"}, hostPub, 1*time.Second)
	if err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("forged response must be rejected, got %v", err)
	}
}

// enforce: a reference the host did not approve is denied.
func TestEnforceAllowlist(t *testing.T) {
	spool := t.TempDir()
	stop, hostPub := startHost(t, spool, HostOpts{
		Resolver: fakeResolver{m: map[string]string{"op://x/y/z": secret}},
		Allowed:  func(string) bool { return false },
		Enforce:  true,
	})
	defer close(stop)
	_, err := Fetch(spool, NewExecID(), []string{"op://x/y/z"}, hostPub, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "ref-not-approved") {
		t.Fatalf("enforce should deny, got %v", err)
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
