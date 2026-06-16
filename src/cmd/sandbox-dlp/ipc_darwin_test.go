//go:build darwin

package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// fakeMounter records mount/unmount calls without touching a real driver.
type fakeMounter struct {
	mu                 sync.Mutex
	mounted, unmounted int
}

func (f *fakeMounter) Name() string { return "fake" }

func (f *fakeMounter) Mount(execID, mountpoint, root string, _ *projection.Registry) (func() error, error) {
	f.mu.Lock()
	f.mounted++
	f.mu.Unlock()
	return func() error {
		f.mu.Lock()
		f.unmounted++
		f.mu.Unlock()
		return nil
	}, nil
}

// startTestServer binds a control socket and serves s on it. The socket lives under a
// short /tmp dir because macOS caps an AF_UNIX path at 104 bytes (the default per-test
// TMPDIR under /var/folders is too long).
func startTestServer(t *testing.T, s *Service) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sgdlp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	go serveControl(ln, s)
	t.Cleanup(func() { _ = ln.Close() })
	return sock
}

// send dials the socket, sends one control request, and returns the response.
func send(t *testing.T, sock string, req projection.ControlRequest) projection.Response {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}
	var resp projection.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestControl_RegisterServeDeregister(t *testing.T) {
	fm := &fakeMounter{}
	s := newService(fm)
	sock := startTestServer(t, s)

	root := t.TempDir()
	envFile := filepath.Join(root, ".env")
	tok, _ := projection.NewToken()
	reg := projection.RegisterRequest{
		ExecID:     "e1",
		Root:       root,
		Mountpoint: filepath.Join(t.TempDir(), "mnt"),
		Files:      []projection.RenderedFile{{Path: envFile, Content: []byte("PASSWORD=REAL\n")}},
		RootPID:    os.Getpid(), // our own reads count as in-subtree
		Token:      tok,
		TTLSeconds: 30,
	}

	if r := send(t, sock, projection.ControlRequest{Op: projection.OpRegister, Register: &reg}); !r.OK {
		t.Fatalf("register failed: %q", r.Error)
	}
	if fm.mounted != 1 {
		t.Fatalf("expected 1 mount, got %d", fm.mounted)
	}

	// The registry now serves the rendered bytes to this process (in subtree)…
	if got, serve := s.reg.Resolve(envFile, os.Getpid()); !serve || string(got) != "PASSWORD=REAL\n" {
		t.Fatalf("not served to subtree: serve=%v got=%q", serve, got)
	}
	// …but not to pid 1 (outside the subtree).
	if _, serve := s.reg.Resolve(envFile, 1); serve {
		t.Fatal("pid 1 must not be served the value")
	}

	// Status reflects the active exec and driver.
	st := send(t, sock, projection.ControlRequest{Op: projection.OpStatus})
	if !st.OK || st.Active != 1 || st.Driver != "fake" {
		t.Fatalf("status wrong: %+v", st)
	}

	// Deregister with the right token tears the exec down and unmounts.
	if r := send(t, sock, projection.ControlRequest{Op: projection.OpDeregister,
		Deregister: &projection.DeregisterRequest{ExecID: "e1", Token: tok}}); !r.OK {
		t.Fatalf("deregister failed: %q", r.Error)
	}
	if fm.unmounted != 1 {
		t.Fatalf("expected 1 unmount, got %d", fm.unmounted)
	}
	if _, serve := s.reg.Resolve(envFile, os.Getpid()); serve {
		t.Fatal("nothing should be served after deregister")
	}
}

func TestControl_DeregisterWrongTokenRejected(t *testing.T) {
	fm := &fakeMounter{}
	s := newService(fm)
	sock := startTestServer(t, s)

	root := t.TempDir()
	envFile := filepath.Join(root, ".env")
	tok, _ := projection.NewToken()
	reg := projection.RegisterRequest{
		ExecID: "e1", Root: root, Mountpoint: filepath.Join(t.TempDir(), "mnt"),
		Files:   []projection.RenderedFile{{Path: envFile, Content: []byte("x")}},
		RootPID: os.Getpid(), Token: tok, TTLSeconds: 30,
	}
	send(t, sock, projection.ControlRequest{Op: projection.OpRegister, Register: &reg})

	if r := send(t, sock, projection.ControlRequest{Op: projection.OpDeregister,
		Deregister: &projection.DeregisterRequest{ExecID: "e1", Token: "wrong"}}); r.OK {
		t.Fatal("deregister with a wrong token must be rejected")
	}
	if fm.unmounted != 0 {
		t.Fatal("a rejected deregister must not unmount")
	}
}

func TestControl_InvalidRegisterRejected(t *testing.T) {
	s := newService(&fakeMounter{})
	sock := startTestServer(t, s)
	// Missing files / bad root → Validate fails before any mount.
	bad := projection.RegisterRequest{ExecID: "e1", Root: "relative", RootPID: 1, Token: "t"}
	if r := send(t, sock, projection.ControlRequest{Op: projection.OpRegister, Register: &bad}); r.OK {
		t.Fatal("an invalid registration must be rejected")
	}
}

func TestControl_MalformedRequest(t *testing.T) {
	s := newService(&fakeMounter{})
	sock := startTestServer(t, s)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("this is not json\n"))
	var resp projection.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("server should still reply: %v", err)
	}
	if resp.OK {
		t.Fatal("malformed request must not be OK")
	}
}
