package broker

import (
	"net"
	"strings"
	"testing"
	"time"
)

// pipeConns returns a pair of connected in-memory net.Conns.
func pipeConns() (net.Conn, net.Conn) { return net.Pipe() }

// B-01: a bootstrap without a certificate pin must be refused (no unpinned TLS).
func TestClientRefusesUnpinnedBootstrap(t *testing.T) {
	b64, _ := tokenPair(t)
	bs := Bootstrap{Session: "s", Plan: "A", DialAddr: "127.0.0.1:1", TokenB64: b64, CertFP: "", TTLUnix: time.Now().Add(time.Hour).Unix()}
	_, err := Client{Bootstrap: bs}.Resolve([]string{"op://a/b/c"})
	if err == nil || !strings.Contains(err.Error(), "no certificate pin") {
		t.Fatalf("expected refusal on empty cert pin, got %v", err)
	}
}

// B-02: a short capability token must be rejected before any handshake.
func TestServerAndClientRejectShortToken(t *testing.T) {
	spool := t.TempDir()
	short := "c2hvcnQ=" // "short" (5 bytes) base64
	bs := Bootstrap{Session: "s", Plan: "A", DialAddr: "127.0.0.1:1", TokenB64: short, CertFP: "ab", TTLUnix: time.Now().Add(time.Hour).Unix()}
	if _, err := (Client{Bootstrap: bs, Spool: spool}).Resolve([]string{"op://a/b/c"}); err == nil || !strings.Contains(err.Error(), "token too short") {
		t.Fatalf("client should reject short token, got %v", err)
	}
	// Server side: a Handler with a short token refuses to serve.
	h := &Handler{Token: []byte("short"), Resolver: fakeResolver{}}
	c1, c2 := pipeConns()
	defer c2.Close()
	if err := h.serve(c1); err == nil || !strings.Contains(err.Error(), "token too short") {
		t.Fatalf("server should refuse short token, got %v", err)
	}
}

// B-06: a resolve request with too many refs is rejected.
func TestTooManyRefsRejected(t *testing.T) {
	spool := t.TempDir()
	b64, tok := tokenPair(t)
	h := &Handler{Token: tok, Resolver: fakeResolver{m: map[string]string{}}}
	go func() {
		_ = RunServer(ServerConfig{Session: "many", Spool: spool, VmnetIP: "127.0.0.1", Port: 0, TokenB64: b64, Handler: h, IdleTimeout: 2 * time.Second})
	}()
	bs := waitBootstrap(t, spool, "many")
	refs := make([]string, maxRefsPerRequest+5)
	for i := range refs {
		refs[i] = "op://v/i/x" // distinct after dedupe? same ref dedupes to 1
	}
	// Use distinct refs to exceed the cap.
	for i := range refs {
		refs[i] = "op://v/i/x" + string(rune('a'+i%26)) + string(rune('0'+i/26))
	}
	_, err := Client{Bootstrap: bs, Spool: spool}.Resolve(refs)
	if err == nil || !strings.Contains(err.Error(), "too-many-refs") {
		t.Fatalf("expected too-many-refs, got %v", err)
	}
}

// B-07: the broker refuses to bind all interfaces.
func TestServerRefusesBindAllInterfaces(t *testing.T) {
	err := RunServer(ServerConfig{Session: "x", Spool: t.TempDir(), VmnetIP: "0.0.0.0", Port: 0, TokenB64: "x", Handler: &Handler{}})
	if err == nil || !strings.Contains(err.Error(), "all interfaces") {
		t.Fatalf("expected refusal to bind 0.0.0.0, got %v", err)
	}
}

// B-05: ambiguous discovery (two live bootstraps, no session) fails closed.
func TestDiscoverAmbiguousFailsClosed(t *testing.T) {
	spool := t.TempDir()
	for _, s := range []string{"s1", "s2"} {
		_ = WriteBootstrap(spool, Bootstrap{Session: s, Plan: "A", DialAddr: "127.0.0.1:1", TokenB64: "dG9rZW4=", CertFP: "x", TTLUnix: time.Now().Add(time.Hour).Unix()})
	}
	if _, _, ok := DiscoverBootstrap("", []string{spool}); ok {
		t.Fatal("ambiguous discovery (2 live bootstraps) must fail closed")
	}
	// With an exact session it still resolves.
	if _, _, ok := DiscoverBootstrap("s1", []string{spool}); !ok {
		t.Fatal("exact-session discovery should succeed")
	}
}
