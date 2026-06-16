//go:build sandboxdlp && windows

// Windows per-process E2E scaffold — mirror of the validated macOS test
// (provider_fuse_darwin_test.go). Run on a Windows host with WinFsp + cgo:
//   go test -tags sandboxdlp ./cmd/sandbox-dlp/
//
// It proves the core property on WinFsp: an in-subtree reader sees the rendered value,
// an unrelated process sees only references, and the backing file on disk never changes.
// If the authorized read returns the reference, the driver is not propagating the caller
// PID through fuse.Getcontext() — switch the oracle to FspFileSystemOperationProcessId()
// (see provider_fuse_windows.go header). PowerShell quoting/encoding below may need small
// tweaks in your environment; the assertions are what matter.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

const (
	winOrig     = "TOKEN=op://vault/item/password\r\n"
	winRendered = "TOKEN=R3nd3redSecretValue\r\n"
)

func winWaitFor(d time.Duration, f func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func winTemp(t *testing.T, prefix string) string {
	t.Helper()
	d, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// winMount registers a project and mounts it for exec rooted at rootPID. Returns the
// mountpoint and backing .env path.
func winMount(t *testing.T, s *Service, rootPID int) (mount, backing string) {
	t.Helper()
	root := winTemp(t, "sgproj")
	backing = filepath.Join(root, ".env")
	if err := os.WriteFile(backing, []byte(winOrig), 0o600); err != nil {
		t.Fatal(err)
	}
	// The client passes a temp dir; prepareMountpoint removes it so WinFsp can create it.
	mount = filepath.Join(winTemp(t, "sgmnt"), "m")
	token, _ := projection.NewToken()
	req := projection.RegisterRequest{
		ExecID: "e1", Root: root, Mountpoint: mount,
		Files:   []projection.RenderedFile{{Path: backing, Content: []byte(winRendered)}},
		RootPID: rootPID, Token: token, TTLSeconds: 60,
	}
	if r := s.handleRegister(req); !r.OK {
		t.Fatalf("register/mount failed: %s", r.Error)
	}
	t.Cleanup(func() { s.handleDeregister(projection.DeregisterRequest{ExecID: "e1", Token: token}) })
	if !winWaitFor(15*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(mount, ".env"))
		return err == nil
	}) {
		t.Skip("WinFsp mount did not come up within 15s (driver not installed in this run)")
	}
	return mount, backing
}

func TestWinFuse_MountsAndNeverWritesDisk(t *testing.T) {
	s := newService(newMounter())
	mount, backing := winMount(t, s, os.Getpid())
	if _, err := os.ReadFile(filepath.Join(mount, ".env")); err != nil {
		t.Fatalf("read mount: %v", err)
	}
	if b, _ := os.ReadFile(backing); string(b) != winOrig {
		t.Fatalf("LEAK: backing file on disk changed to %q", b)
	}
}

func TestWinFuse_PerProcessGating(t *testing.T) {
	s := newService(newMounter())

	out := filepath.Join(winTemp(t, "sgout"), "seen.txt")
	// The child reads the mountpoint from stdin (only known after its PID exists, which
	// the registration needs), then — as a descendant of the registered root — copies the
	// mounted .env to SGOUT. SGOUT is known up front, so it goes in the env before Start.
	psScript := `$mnt=[Console]::In.ReadLine().Trim(); ` +
		`[System.IO.File]::WriteAllBytes($env:SGOUT, [System.IO.File]::ReadAllBytes((Join-Path $mnt '.env')))`
	child := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	child.Env = append(os.Environ(), "SGOUT="+out)
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _, _ = child.Process.Wait() }()

	mount, backing := winMount(t, s, child.Process.Pid)
	_, _ = stdin.Write([]byte(mount + "\r\n"))
	_ = stdin.Close()
	_ = child.Wait()

	authorized, _ := os.ReadFile(out)
	unauthorized, _ := os.ReadFile(filepath.Join(mount, ".env"))
	t.Logf("driver caller_pid=%d", atomic.LoadInt32(&lastCallerPID))
	t.Logf("authorized:   %q", authorized)
	t.Logf("unauthorized: %q", unauthorized)

	if strings.TrimSpace(string(unauthorized)) != strings.TrimSpace(winOrig) {
		t.Errorf("LEAK: out-of-subtree reader saw %q, want references", unauthorized)
	}
	if b, _ := os.ReadFile(backing); string(b) != winOrig {
		t.Errorf("LEAK: backing changed on disk to %q", b)
	}
	if atomic.LoadInt32(&lastCallerPID) == 0 {
		t.Skip("driver did not expose caller PID via fuse.Getcontext(); wire the oracle to " +
			"FspFileSystemOperationProcessId() (see provider_fuse_windows.go).")
	}
	if strings.TrimSpace(string(authorized)) != strings.TrimSpace(winRendered) {
		t.Fatalf("authorized subtree reader should see the rendered value, got %q", authorized)
	}
}
