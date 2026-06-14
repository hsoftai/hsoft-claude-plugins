package broker

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func tokenPair(t *testing.T) (string, []byte) {
	t.Helper()
	b64, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	return b64, mustDecode(t, b64)
}

func mustDecode(t *testing.T, b64 string) []byte {
	t.Helper()
	bs := Bootstrap{TokenB64: b64}
	tok := bs.Token()
	if len(tok) == 0 {
		t.Fatalf("token decode failed")
	}
	return tok
}

func waitBootstrap(t *testing.T, spool, session string) Bootstrap {
	t.Helper()
	for i := 0; i < 200; i++ {
		if b, err := ReadBootstrap(spool, session); err == nil {
			return b
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("bootstrap never appeared")
	return Bootstrap{}
}

// Plan A end-to-end over localhost: host listens, VM dials, value delivered.
func TestPlanA_EndToEnd(t *testing.T) {
	spool := t.TempDir()
	b64, tok := tokenPair(t)
	fake := fakeResolver{m: map[string]string{"op://v/i/password": "S3cr3tValue!"}}

	var got []string
	var mu sync.Mutex
	h := &Handler{
		Token:    tok,
		Resolver: fake,
		OnResolve: func(ref, value string) {
			mu.Lock()
			got = append(got, ref+"="+value)
			mu.Unlock()
		},
	}
	go func() {
		_ = RunServer(ServerConfig{
			Session: "sess-A", Spool: spool, VmnetIP: "127.0.0.1", Port: 0,
			TokenB64: b64, Handler: h, IdleTimeout: 2 * time.Second,
		})
	}()

	bs := waitBootstrap(t, spool, "sess-A")
	if bs.Plan != "A" || bs.DialAddr == "" {
		t.Fatalf("expected Plan A bootstrap, got %+v", bs)
	}
	c := Client{Bootstrap: bs, Spool: spool, ExecID: "exec1"}
	vals, err := c.Resolve([]string{"op://v/i/password"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if vals["op://v/i/password"] != "S3cr3tValue!" {
		t.Fatalf("wrong value: %+v", vals)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "op://v/i/password=S3cr3tValue!" {
		t.Fatalf("OnResolve not called correctly: %+v", got)
	}
}

// A client with the wrong token must be rejected.
func TestPlanA_AuthFailure(t *testing.T) {
	spool := t.TempDir()
	b64, tok := tokenPair(t)
	h := &Handler{Token: tok, Resolver: fakeResolver{m: map[string]string{"op://a/b/c": "x"}}}
	go func() {
		_ = RunServer(ServerConfig{Session: "sess-bad", Spool: spool, VmnetIP: "127.0.0.1", Port: 0, TokenB64: b64, Handler: h, IdleTimeout: 2 * time.Second})
	}()
	bs := waitBootstrap(t, spool, "sess-bad")

	// Tamper: replace the token in the bootstrap the client uses.
	wrong, _ := NewToken()
	bs.TokenB64 = wrong
	c := Client{Bootstrap: bs, Spool: spool}
	if _, err := c.Resolve([]string{"op://a/b/c"}); err == nil {
		t.Fatal("expected auth failure with wrong token")
	}
}

// enforce policy denies a reference outside the allowlist; audit policy allows it.
func TestAllowlistPolicy(t *testing.T) {
	run := func(enforce bool) error {
		spool := t.TempDir()
		b64, tok := tokenPair(t)
		h := &Handler{
			Token:    tok,
			Resolver: fakeResolver{m: map[string]string{"op://x/y/z": "v"}},
			Allowed:  func(ref string) bool { return false }, // nothing approved
			Enforce:  enforce,
		}
		session := fmt.Sprintf("sess-pol-%v", enforce)
		go func() {
			_ = RunServer(ServerConfig{Session: session, Spool: spool, VmnetIP: "127.0.0.1", Port: 0, TokenB64: b64, Handler: h, IdleTimeout: 2 * time.Second})
		}()
		bs := waitBootstrap(t, spool, session)
		_, err := Client{Bootstrap: bs, Spool: spool}.Resolve([]string{"op://x/y/z"})
		return err
	}

	if err := run(true); err == nil || !strings.Contains(err.Error(), "ref-not-approved") {
		t.Fatalf("enforce should deny with ref-not-approved, got %v", err)
	}
	if err := run(false); err != nil {
		t.Fatalf("audit policy should allow, got %v", err)
	}
}

// Plan B over localhost: host dials into the VM's listener (rendezvous via spool).
func TestPlanB_EndToEnd(t *testing.T) {
	orig := localIP
	localIP = func() string { return "127.0.0.1" }
	defer func() { localIP = orig }()

	spool := t.TempDir()
	b64, tok := tokenPair(t)
	fake := fakeResolver{m: map[string]string{"op://v/i/db": "PlanB-Secret"}}
	h := &Handler{Token: tok, Resolver: fake}

	// Host in Plan B mode: we drive dialLoop directly with a free port bootstrap.
	port := freePort(t)
	bs := Bootstrap{Session: "sess-B", Plan: "B", Port: port, TokenB64: b64, TTLUnix: time.Now().Add(time.Hour).Unix()}
	if err := WriteBootstrap(spool, bs); err != nil {
		t.Fatal(err)
	}
	cfg := ServerConfig{Session: "sess-B", Spool: spool, Handler: h, IdleTimeout: 2 * time.Second}
	go func() { _ = cfg.dialLoop(bs) }()

	// VM client listens and waits for the host to dial in.
	c := Client{Bootstrap: bs, Spool: spool, ExecID: "execB"}
	vals, err := c.Resolve([]string{"op://v/i/db"})
	if err != nil {
		t.Fatalf("plan B resolve: %v", err)
	}
	if vals["op://v/i/db"] != "PlanB-Secret" {
		t.Fatalf("wrong value: %+v", vals)
	}
}

func TestBootstrap_WriteReadDiscoverExpiry(t *testing.T) {
	spool := t.TempDir()
	live := Bootstrap{Session: "s1", Plan: "A", DialAddr: "127.0.0.1:1", TokenB64: "dG9rZW4=", TTLUnix: time.Now().Add(time.Hour).Unix()}
	expired := Bootstrap{Session: "s2", Plan: "A", DialAddr: "127.0.0.1:2", TokenB64: "dG9rZW4=", TTLUnix: time.Now().Add(-time.Hour).Unix()}
	if err := WriteBootstrap(spool, live); err != nil {
		t.Fatal(err)
	}
	if err := WriteBootstrap(spool, expired); err != nil {
		t.Fatal(err)
	}

	// Direct read by session.
	if b, err := ReadBootstrap(spool, "s1"); err != nil || b.DialAddr != "127.0.0.1:1" {
		t.Fatalf("read s1: %v %+v", err, b)
	}
	// Discover by session.
	if b, sp, ok := DiscoverBootstrap("s1", []string{spool}); !ok || sp != spool || b.Session != "s1" {
		t.Fatalf("discover s1 failed: %+v %q %v", b, sp, ok)
	}
	// Discover without a session skips the expired one and returns the live one.
	if b, _, ok := DiscoverBootstrap("", []string{spool}); !ok || b.Session != "s1" {
		t.Fatalf("discover live failed: %+v %v", b, ok)
	}
	// Files are written 0600.
	info, err := os.Stat(bootstrapPath(spool, "s1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("bootstrap not 0600: %v", info.Mode())
	}
}

// The secret value must never be written into the spool (only control plane).
func TestNoSecretInSpool(t *testing.T) {
	spool := t.TempDir()
	b64, tok := tokenPair(t)
	secret := "TOPSECRET-DO-NOT-PERSIST"
	h := &Handler{Token: tok, Resolver: fakeResolver{m: map[string]string{"op://v/i/x": secret}}}
	go func() {
		_ = RunServer(ServerConfig{Session: "sess-leak", Spool: spool, VmnetIP: "127.0.0.1", Port: 0, TokenB64: b64, Handler: h, IdleTimeout: 2 * time.Second})
	}()
	bs := waitBootstrap(t, spool, "sess-leak")
	if _, err := (Client{Bootstrap: bs, Spool: spool}).Resolve([]string{"op://v/i/x"}); err != nil {
		t.Fatal(err)
	}
	// Walk the whole spool tree; the value must not appear in any file.
	_ = filepath.Walk(spool, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, _ := os.ReadFile(p)
		if strings.Contains(string(data), secret) {
			t.Fatalf("secret value leaked into spool file %s", p)
		}
		return nil
	})
}

func freePort(t *testing.T) int {
	t.Helper()
	// Bind :0, read the chosen port, release it for the actual listener.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
