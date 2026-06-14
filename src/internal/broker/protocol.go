package broker

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// handshakeTimeout bounds a full auth+resolve exchange.
	handshakeTimeout = 20 * time.Second
	// phaseTimeout bounds each individual read so a slow-drip client cannot tie
	// up the (sequentially served) broker for the whole handshake window.
	phaseTimeout = 8 * time.Second
	// minTokenLen rejects empty/short capability tokens: HMAC with a tiny key is
	// guessable, and Token() swallows decode errors, so guard here.
	minTokenLen = 32
	// maxRefsPerRequest caps the resolve fan-out; each ref spawns a vault CLI.
	maxRefsPerRequest = 32
	// maxConnBytes caps total bytes read on one connection (the exchange is tiny),
	// preventing an unbounded line from exhausting host memory.
	maxConnBytes = 256 * 1024
)

// msg is one newline-delimited JSON message on the wire.
type msg struct {
	Type   string            `json:"type"` // hello | auth | auth_ok | resolve | values | error
	Nonce  string            `json:"nonce,omitempty"`
	MAC    string            `json:"mac,omitempty"`
	ExecID string            `json:"exec_id,omitempty"`
	Refs   []string          `json:"refs,omitempty"`
	Values map[string]string `json:"values,omitempty"`
	Error  string            `json:"error,omitempty"`
}

// Resolver is the minimal vault capability the broker needs; satisfied by
// *vault.Resolver. ResolveString returns the resolved value(s) of a reference.
type Resolver interface {
	ResolveString(s string) (string, []string, error)
}

// Handler is the host-side resolving authority. It owns the per-session
// capability token and the vault resolver, and enforces the ref allowlist.
type Handler struct {
	Token     []byte
	Resolver  Resolver
	Allowed   func(ref string) bool   // nil => allow all
	Enforce   bool                    // true => deny refs not in the allowlist
	OnResolve func(ref, value string) // register value (seen/cache) + audit; nil => noop
}

// serve runs the protocol-server side of one connection (the host): it
// challenges the peer, verifies the peer holds the token, proves its own
// identity, then answers a single resolve request. The secret values are written
// only to this socket.
func (h *Handler) serve(conn net.Conn) error {
	defer conn.Close()
	if len(h.Token) < minTokenLen {
		return fmt.Errorf("broker token too short (refusing to serve)")
	}
	rw := bufio.NewReadWriter(bufio.NewReader(io.LimitReader(conn, maxConnBytes)), bufio.NewWriter(conn))

	n1, err := randomNonce()
	if err != nil {
		return err
	}
	if err := writeMsg(rw, msg{Type: "hello", Nonce: n1}); err != nil {
		return err
	}

	a, err := readPhase(conn, rw)
	if err != nil {
		return err
	}
	if a.Type != "auth" || !verifyMAC(h.Token, n1, a.MAC) {
		_ = writeMsg(rw, msg{Type: "error", Error: "auth"})
		return fmt.Errorf("client authentication failed")
	}
	// Prove our own knowledge of the token back to the client (mutual auth).
	if err := writeMsg(rw, msg{Type: "auth_ok", MAC: computeMAC(h.Token, a.Nonce)}); err != nil {
		return err
	}

	req, err := readPhase(conn, rw)
	if err != nil {
		return err
	}
	if req.Type != "resolve" {
		return writeMsg(rw, msg{Type: "error", Error: "protocol"})
	}
	refs := capRefs(req.Refs)
	if len(req.Refs) > maxRefsPerRequest {
		return writeMsg(rw, msg{Type: "error", Error: "too-many-refs"})
	}

	out := make(map[string]string, len(refs))
	for _, ref := range refs {
		// enforce (default): a reference not in the host-observed allowlist is
		// denied outright. audit (opt-in): the allowlist is advisory — the ref is
		// still resolved but the caller's Allowed/OnResolve can log it. Default is
		// enforce so the broker never serves an unobserved reference.
		if h.Allowed != nil && !h.Allowed(ref) && h.Enforce {
			return writeMsg(rw, msg{Type: "error", Error: "ref-not-approved"})
		}
		val, verr := h.resolveOne(ref)
		if verr != nil {
			// Do not echo the resolver error verbatim (it could contain context);
			// return a generic message.
			return writeMsg(rw, msg{Type: "error", Error: "resolve-failed"})
		}
		out[ref] = val
		if h.OnResolve != nil {
			h.OnResolve(ref, val)
		}
	}
	return writeMsg(rw, msg{Type: "values", Values: out})
}

// dedupeRefs removes empty and duplicate references, preserving order.
func dedupeRefs(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, r := range in {
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

// capRefs de-duplicates and bounds the reference list (server-side processing).
func capRefs(in []string) []string {
	out := dedupeRefs(in)
	if len(out) > maxRefsPerRequest {
		out = out[:maxRefsPerRequest]
	}
	return out
}

// readPhase refreshes the per-message deadline before reading, bounding slow-drip.
func readPhase(conn net.Conn, rw *bufio.ReadWriter) (msg, error) {
	_ = conn.SetReadDeadline(time.Now().Add(phaseTimeout))
	return readMsg(rw)
}

func (h *Handler) resolveOne(ref string) (string, error) {
	s, vals, err := h.Resolver.ResolveString(ref)
	if err != nil {
		return "", err
	}
	if len(vals) > 0 {
		return vals[0], nil
	}
	return s, nil
}

// request runs the protocol-client side (the VM): it authenticates mutually with
// the token and asks the host to resolve refs, returning ref->value. The values
// exist only in this process's memory.
func request(conn net.Conn, token []byte, execID string, refs []string) (map[string]string, error) {
	if len(token) < minTokenLen {
		return nil, fmt.Errorf("capability token too short")
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	rw := bufio.NewReadWriter(bufio.NewReader(io.LimitReader(conn, maxConnBytes)), bufio.NewWriter(conn))

	hello, err := readPhase(conn, rw)
	if err != nil {
		return nil, err
	}
	if hello.Type != "hello" {
		return nil, fmt.Errorf("unexpected message %q", hello.Type)
	}
	n2, err := randomNonce()
	if err != nil {
		return nil, err
	}
	if err := writeMsg(rw, msg{Type: "auth", ExecID: execID, Nonce: n2, MAC: computeMAC(token, hello.Nonce)}); err != nil {
		return nil, err
	}
	ok, err := readPhase(conn, rw)
	if err != nil {
		return nil, err
	}
	if ok.Type == "error" {
		return nil, fmt.Errorf("broker: %s", ok.Error)
	}
	if ok.Type != "auth_ok" || !verifyMAC(token, n2, ok.MAC) {
		return nil, fmt.Errorf("broker authentication failed (possible impostor)")
	}
	// Send de-duplicated refs (no silent cap): if the caller exceeds the limit the
	// server rejects with too-many-refs rather than dropping references.
	if err := writeMsg(rw, msg{Type: "resolve", Refs: dedupeRefs(refs)}); err != nil {
		return nil, err
	}
	resp, err := readPhase(conn, rw)
	if err != nil {
		return nil, err
	}
	if resp.Type == "error" {
		return nil, fmt.Errorf("broker: %s", resp.Error)
	}
	if resp.Type != "values" {
		return nil, fmt.Errorf("unexpected message %q", resp.Type)
	}
	return resp.Values, nil
}

func writeMsg(rw *bufio.ReadWriter, m msg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if _, err := rw.Write(append(b, '\n')); err != nil {
		return err
	}
	return rw.Flush()
}

func readMsg(rw *bufio.ReadWriter) (msg, error) {
	// Every message is written terminated by '\n'. Require a clean, fully
	// delimited line: a non-nil error (EOF/limit/reset mid-line) is a failure,
	// never a partially parsed message.
	line, err := rw.ReadBytes('\n')
	if err != nil {
		return msg{}, err
	}
	var m msg
	if e := json.Unmarshal(line, &m); e != nil {
		return msg{}, e
	}
	return m, nil
}

func computeMAC(token []byte, nonce string) string {
	m := hmac.New(sha256.New, token)
	m.Write([]byte(nonce))
	return hex.EncodeToString(m.Sum(nil))
}

func verifyMAC(token []byte, nonce, mac string) bool {
	return hmac.Equal([]byte(computeMAC(token, nonce)), []byte(mac))
}

func randomNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
