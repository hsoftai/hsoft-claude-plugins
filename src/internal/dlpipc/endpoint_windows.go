//go:build windows

package dlpipc

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const dialTimeout = 3 * time.Second

// Endpoint is the named pipe the client dials and the service hosts. It is keyed to the
// current user's SID so a different user cannot reach (or impersonate) the service; the
// service additionally hosts the pipe with an owner-only ACL.
func Endpoint() (string, error) {
	sid, err := CurrentUserSID()
	if err != nil {
		return "", err
	}
	return `\\.\pipe\secrets-guard-dlp-` + sid, nil
}

// Dial connects to the service control pipe.
func Dial() (net.Conn, error) {
	ep, err := Endpoint()
	if err != nil {
		return nil, err
	}
	t := dialTimeout
	return winio.DialPipe(ep, &t)
}

// CurrentUserSID returns the string SID of the user running this process.
func CurrentUserSID() (string, error) {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}
