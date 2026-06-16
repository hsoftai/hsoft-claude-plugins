//go:build sandboxdlp && darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

const (
	origEnv     = "TOKEN=op://vault/item/password\n"
	renderedEnv = "TOKEN=R3nd3redSecretValue\n"
)

// waitFor polls until f() succeeds or the deadline passes.
func waitFor(d time.Duration, f func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// mustShortTemp makes a temp dir under /tmp (short path: macOS NFS/AF_UNIX path limits).
func mustShortTemp(t *testing.T, prefix string) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// mountProject sets up a real mount of a temp project whose .env holds origEnv, rendered
// to renderedEnv for the exec rooted at rootPID. It returns the mountpoint and the
// backing .env path, and registers cleanup (deregister + unmount).
func mountProject(t *testing.T, s *Service, execID string, rootPID int) (mount, backing string) {
	t.Helper()
	root := mustShortTemp(t, "sgproj")
	backing = filepath.Join(root, ".env")
	if err := os.WriteFile(backing, []byte(origEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	mount = mustShortTemp(t, "sgmnt")
	token, _ := projection.NewToken()
	req := projection.RegisterRequest{
		ExecID: execID, Root: root, Mountpoint: mount,
		Files:   []projection.RenderedFile{{Path: backing, Content: []byte(renderedEnv)}},
		RootPID: rootPID, Token: token, TTLSeconds: 60,
	}
	if r := s.handleRegister(req); !r.OK {
		t.Fatalf("register/mount failed: %s", r.Error)
	}
	t.Cleanup(func() { s.handleDeregister(projection.DeregisterRequest{ExecID: execID, Token: token}) })

	if !waitFor(10*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(mount, ".env"))
		return err == nil
	}) {
		t.Skip("mount did not come up within 10s (FUSE driver/daemon not available in this run)")
	}
	return mount, backing
}

// driverPropagatesPID reports whether the mounted driver exposes the real caller PID to
// the read handler. fuse-t (NFS backend) always reports 0, which makes per-process
// gating impossible (everything fails closed to the original reference). macFUSE/FSKit
// pass the real PID.
func driverPropagatesPID() bool { return atomic.LoadInt32(&lastCallerPID) != 0 }

// TestFuseMount_MountsAndNeverWritesDisk proves the mount works and — regardless of
// whether the driver supports per-process gating — the real backing file on disk is
// NEVER rewritten with the value. This is the non-negotiable invariant and must hold on
// every driver.
func TestFuseMount_MountsAndNeverWritesDisk(t *testing.T) {
	s := newService(newMounter())
	mount, backing := mountProject(t, s, "e1", os.Getpid())

	// Read through the mount (rendered or original depending on the driver's PID support).
	if _, err := os.ReadFile(filepath.Join(mount, ".env")); err != nil {
		t.Fatalf("read mount: %v", err)
	}
	// The real disk must still hold ONLY the reference — the value never touches disk.
	if b, _ := os.ReadFile(backing); string(b) != origEnv {
		t.Fatalf("LEAK: backing file on disk changed to %q", b)
	}
}

// TestFuseMount_PerProcessGating is the decisive experiment. On a PID-propagating driver
// (macFUSE) the authorized subtree reads the rendered value while an unrelated process
// reads only references. On a non-propagating driver (fuse-t) it asserts the safe
// fallback — NO process gets the value (no leak) — and skips with a clear explanation.
func TestFuseMount_PerProcessGating(t *testing.T) {
	s := newService(newMounter())

	// Authorized subtree root: waits for the mountpoint on stdin, then reads .env (as a
	// descendant) into an output file.
	out := filepath.Join(mustShortTemp(t, "sgout"), "seen.txt")
	child := exec.Command("/bin/sh", "-c", `IFS= read MNT; cat "$MNT/.env" > "`+out+`" 2>&1`)
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _, _ = child.Process.Wait() }()

	mount, backing := mountProject(t, s, "e1", child.Process.Pid)

	if _, err := stdin.Write([]byte(mount + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	if err := child.Wait(); err != nil {
		t.Fatalf("child read failed: %v", err)
	}

	authorized, _ := os.ReadFile(out)                            // descendant of root
	unauthorized, _ := os.ReadFile(filepath.Join(mount, ".env")) // this test (not a descendant)
	t.Logf("driver caller_pid=%d", atomic.LoadInt32(&lastCallerPID))
	t.Logf("authorized (in-subtree) read:   %q", authorized)
	t.Logf("unauthorized (out-of-subtree):  %q", unauthorized)

	// Invariant on every driver: the out-of-subtree reader and the disk never see the value.
	if string(unauthorized) != origEnv {
		t.Errorf("LEAK: out-of-subtree reader saw %q, want only references", unauthorized)
	}
	if b, _ := os.ReadFile(backing); string(b) != origEnv {
		t.Errorf("LEAK: backing changed on disk to %q", b)
	}

	if !driverPropagatesPID() {
		if string(authorized) != origEnv {
			t.Fatalf("non-PID driver must fail closed for everyone, but authorized saw %q", authorized)
		}
		t.Skip("driver does not expose caller PID (fuse-t NFS backend, pid=0): per-process " +
			"gating is impossible — it fails closed (no leak). True per-process rendering " +
			"requires macFUSE or FSKit.")
	}

	// PID-propagating driver (macFUSE): the authorized subtree must see the rendered value.
	if string(authorized) != renderedEnv {
		t.Fatalf("authorized subtree reader should see the rendered value, got %q", authorized)
	}
}
