//go:build !windows

package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/hsoftai/hsoft-claude-plugins/internal/dlpipc"
	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// recorder is a minimal stand-in for the sandbox-dlp control server: it records every
// control request and replies OK (rejecting an invalid registration like the real one).
type recorder struct {
	mu   sync.Mutex
	reqs []projection.ControlRequest
}

func (r *recorder) add(req projection.ControlRequest) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
}

func (r *recorder) ops() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, q := range r.reqs {
		out = append(out, q.Op)
	}
	return out
}

func (r *recorder) lastRegister() *projection.RegisterRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.reqs) - 1; i >= 0; i-- {
		if r.reqs[i].Op == projection.OpRegister {
			return r.reqs[i].Register
		}
	}
	return nil
}

func serveRecorder(ln net.Listener, rec *recorder) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			var req projection.ControlRequest
			if json.NewDecoder(c).Decode(&req) != nil {
				return
			}
			rec.add(req)
			resp := projection.Response{OK: true, Driver: "test"}
			if req.Op == projection.OpRegister && req.Register != nil {
				if err := req.Register.Validate(); err != nil {
					resp = projection.Response{Error: err.Error()}
				}
			}
			_ = json.NewEncoder(c).Encode(resp)
		}(conn)
	}
}

func TestDLPRender_RegistersAndDeregisters(t *testing.T) {
	ep, err := dlpipc.Endpoint()
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(ep) // clear a stale socket
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: ep, Net: "unix"})
	if err != nil {
		t.Skipf("could not bind control endpoint (a real sandbox-dlp may be running): %v", err)
	}
	defer func() { _ = ln.Close(); _ = os.Remove(ep) }()
	rec := &recorder{}
	go serveRecorder(ln, rec)

	// Run from a temp project so cwd() (the registration Root) contains the ref-file.
	// Derive paths from the resolved cwd after chdir (macOS resolves /var → /private/var,
	// which must match the Root the client reports or Validate would reject the file).
	dir := t.TempDir()
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(prev)
	root, _ := os.Getwd()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("TOKEN=op://v/i/p\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	files := []refFile{{path: envPath, refs: []string{"op://v/i/p"}}}
	values := map[string]string{"op://v/i/p": "S3CR3T"}

	mp, dereg, ok := dlpRender(files, values)
	if !ok {
		t.Fatalf("dlpRender should succeed against a healthy service; ops=%v", rec.ops())
	}
	if _, err := os.Stat(mp); err != nil {
		t.Fatalf("mountpoint not created: %v", err)
	}

	reg := rec.lastRegister()
	if reg == nil {
		t.Fatalf("no register recorded; ops=%v", rec.ops())
	}
	if reg.RootPID != os.Getpid() {
		t.Errorf("RootPID = %d, want this process %d", reg.RootPID, os.Getpid())
	}
	if len(reg.Files) != 1 || string(reg.Files[0].Content) != "TOKEN=S3CR3T\n" {
		t.Fatalf("rendered content not sent: %+v", reg.Files)
	}
	// The reference, not the value, is what the client read from disk — the value only
	// ever travels to the service in memory.
	if b, _ := os.ReadFile(envPath); string(b) != "TOKEN=op://v/i/p\n" {
		t.Fatalf("backing .env should still hold the reference, got %q", b)
	}

	dereg()
	if _, err := os.Stat(mp); !os.IsNotExist(err) {
		t.Errorf("mountpoint should be removed after deregister")
	}
	ops := rec.ops()
	if len(ops) == 0 || ops[len(ops)-1] != projection.OpDeregister {
		t.Errorf("expected a deregister last, got ops=%v", ops)
	}
}
