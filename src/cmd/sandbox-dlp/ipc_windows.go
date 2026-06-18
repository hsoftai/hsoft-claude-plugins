//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"

	"github.com/hsoftai/hsoft-claude-plugins/internal/dlpipc"
	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// controlConnTimeout bounds one control connection. A register resolves the ref-files
// (vault CLI calls) and brings up the mount, so it can take several seconds; the deadline
// must exceed that or the service would close the connection mid-register and the client
// would fail closed even though the mount came up.
const controlConnTimeout = 30 * time.Second

// runServe hosts the control named pipe (per-user Windows service entrypoint). The pipe
// is created with an owner-only ACL, so only the same user's processes can connect —
// the Windows equivalent of the unix-socket peer-cred check.
func runServe() {
	pipe, err := dlpipc.Endpoint()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-dlp serve:", err)
		os.Exit(1)
	}
	sddl, err := ownerOnlySDDL()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-dlp serve:", err)
		os.Exit(1)
	}
	ln, err := winio.ListenPipe(pipe, &winio.PipeConfig{SecurityDescriptor: sddl})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-dlp serve:", err)
		os.Exit(1)
	}
	// Ingest the vault credential into this service ONCE at startup (export the local ksm
	// profile into the DPAPI store and remove the global profile), off the register hot
	// path — so the first register is not slowed by the one-time credential setup.
	ensureCredential()
	s := newService(newMounter())
	fmt.Fprintf(os.Stderr, "sandbox-dlp: serving on %s (driver=%s)\n", pipe, s.mnt.Name())
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleControlConn(conn, s)
	}
}

func handleControlConn(conn net.Conn, s *Service) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(controlConnTimeout))
	var req projection.ControlRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(projection.Response{Error: "malformed request"})
		return
	}
	_ = json.NewEncoder(conn).Encode(dispatchControl(s, req))
}

// runStatus dials the control pipe and prints whether the service is up.
func runStatus() {
	resp, err := dlpipc.Call(projection.ControlRequest{Op: projection.OpStatus})
	if err != nil || !resp.OK {
		fmt.Println("sandbox-dlp: not running")
		os.Exit(1)
	}
	fmt.Printf("sandbox-dlp: running (active=%d driver=%s)\n", resp.Active, resp.Driver)
}

// ownerOnlySDDL grants full access to only the current user and SYSTEM, so no other
// account can open the control pipe.
func ownerOnlySDDL() (string, error) {
	sid, err := dlpipc.CurrentUserSID()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("D:P(A;;FA;;;%s)(A;;FA;;;SY)", sid), nil
}
