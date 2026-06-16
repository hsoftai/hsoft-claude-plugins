//go:build darwin

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hsoftai/hsoft-claude-plugins/internal/dlpipc"
	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// The control channel is a unix domain socket in a per-user 0700 directory. Every
// connection is authenticated two ways before any state changes: the kernel-reported
// peer UID must equal ours (LOCAL_PEERCRED — defeats another user connecting), and the
// register/deregister payload carries the per-exec one-time token. The socket only ever
// carries control messages; secret VALUES are never returned over it (they reach a
// process only through a subtree-gated file read).

const controlConnTimeout = 5 * time.Second

// controlSocketPath is the well-known socket path the client dials (shared with the
// secrets-guard CLI via internal/dlpipc so both agree on the per-user endpoint).
func controlSocketPath() (string, error) {
	return dlpipc.Endpoint()
}

// listenControl binds the control socket (replacing a stale one) with 0600 perms.
func listenControl() (*net.UnixListener, error) {
	sock, err := controlSocketPath()
	if err != nil {
		return nil, err
	}
	_ = os.Remove(sock) // clear a stale socket from a previous run
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(sock, 0o600)
	return ln, nil
}

// serveControl accepts control connections until the listener is closed.
func serveControl(ln *net.UnixListener, s *Service) {
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			return // listener closed
		}
		go handleControlConn(conn, s)
	}
}

func handleControlConn(conn *net.UnixConn, s *Service) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(controlConnTimeout))
	if !peerIsOwner(conn) {
		_ = json.NewEncoder(conn).Encode(projection.Response{Error: "unauthorized peer"})
		return
	}
	var req projection.ControlRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(projection.Response{Error: "malformed request"})
		return
	}
	_ = json.NewEncoder(conn).Encode(dispatchControl(s, req))
}

// runServe runs the control service until killed (the launchd LaunchAgent entrypoint).
func runServe() {
	ln, err := listenControl()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-dlp serve:", err)
		os.Exit(1)
	}
	s := newService(newMounter())
	fmt.Fprintf(os.Stderr, "sandbox-dlp: serving on %s (driver=%s)\n", ln.Addr(), s.mnt.Name())
	serveControl(ln, s)
}

// runStatus dials the control socket and prints whether the service is up.
func runStatus() {
	sock, err := controlSocketPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-dlp status:", err)
		os.Exit(1)
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		fmt.Println("sandbox-dlp: not running")
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(controlConnTimeout))
	if err := json.NewEncoder(conn).Encode(projection.ControlRequest{Op: projection.OpStatus}); err != nil {
		fmt.Println("sandbox-dlp: not responding")
		os.Exit(1)
	}
	var resp projection.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil || !resp.OK {
		fmt.Println("sandbox-dlp: not responding")
		os.Exit(1)
	}
	fmt.Printf("sandbox-dlp: running (active=%d driver=%s)\n", resp.Active, resp.Driver)
}

// peerIsOwner reports whether the connecting process runs as our own UID, per the
// kernel (LOCAL_PEERCRED). This is the boundary that stops another user's process from
// registering a projection or probing the service.
func peerIsOwner(conn *net.UnixConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var uid uint32
	var ok bool
	_ = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e == nil && cred != nil {
			uid = cred.Uid
			ok = true
		}
	})
	return ok && uid == uint32(os.Getuid())
}
