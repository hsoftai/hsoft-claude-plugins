// Package dlpipc is the local control transport between the per-user secrets-guard CLI
// (client) and the sandbox-dlp service. The wire protocol lives in internal/projection;
// this package only carries it over the OS-specific channel: a unix domain socket in a
// per-user 0700 directory (macOS/Linux) or an owner-only named pipe (Windows). The
// endpoint is keyed to the current user so only that user's processes can reach it.
package dlpipc

import (
	"encoding/json"
	"time"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

const callTimeout = 5 * time.Second

// Call dials the service, sends one control request, and returns the response. It is the
// only entry point the secrets-guard CLI needs.
func Call(req projection.ControlRequest) (projection.Response, error) {
	conn, err := Dial()
	if err != nil {
		return projection.Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(callTimeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return projection.Response{}, err
	}
	var resp projection.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return projection.Response{}, err
	}
	return resp, nil
}

// Healthy reports whether the service answers a status request.
func Healthy() bool {
	resp, err := Call(projection.ControlRequest{Op: projection.OpStatus})
	return err == nil && resp.OK
}
