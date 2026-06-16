//go:build !windows

package dlpipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// dialTimeout bounds how long a client waits to connect to the service.
const dialTimeout = 3 * time.Second

// ControlDir returns the per-user directory holding the control socket, created 0700.
func ControlDir() (string, error) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("secrets-guard-dlp-%d", os.Getuid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(dir, 0o700) // tighten in case it pre-existed looser
	return dir, nil
}

// Endpoint is the unix socket path the client dials and the service binds.
func Endpoint() (string, error) {
	dir, err := ControlDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "control.sock"), nil
}

// Dial connects to the service control socket.
func Dial() (net.Conn, error) {
	ep, err := Endpoint()
	if err != nil {
		return nil, err
	}
	return net.DialTimeout("unix", ep, dialTimeout)
}
