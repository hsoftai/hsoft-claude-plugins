package projection

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
)

// This file defines the local control protocol between the per-user secrets-guard CLI
// (the client, which resolves vault references) and the sandbox-dlp service (the
// provider, which serves bytes per requesting process). The transport is OS-specific
// and authenticated — a unix domain socket with peer-cred on macOS/Linux, a named pipe
// with an owner-only ACL on Windows — but the wire shape is identical and pure, so it
// is fixed and tested here.
//
// Trust model: both endpoints are the SAME user (sandbox-dlp runs as a per-user
// service). The rendered bytes therefore travel client→provider within one user trust
// domain and live only in the provider's RAM for the exec window. The provider hands a
// value to a READ only when that read's caller is in the registered subtree; it never
// returns a value over this control channel.

// RenderedFile is one declared ref-file and the bytes the authorized subtree should
// read for it. Content is the fully-rendered file (references replaced by values),
// computed by the client; the provider stores it in RAM and never writes it to disk.
type RenderedFile struct {
	Path    string `json:"path"`    // absolute path in the backing project
	Content []byte `json:"content"` // rendered bytes (base64 on the wire)
}

// RegisterRequest activates one exec's projection. RootPID is the process the sandbox
// spawns for the command; the provider tracks its subtree (Job Object / ES feed) and
// serves Files only to reads originating in it. Token is a one-time secret that must be
// presented again to Deregister.
type RegisterRequest struct {
	ExecID     string         `json:"exec_id"`
	Root       string         `json:"root"`       // backing project root (absolute)
	Mountpoint string         `json:"mountpoint"` // where the provider mounts this exec's view
	Files      []RenderedFile `json:"files"`
	RootPID    int            `json:"root_pid"`
	Token      string         `json:"token"`
	TTLSeconds int            `json:"ttl_seconds"` // provider drops the exec after this idle window
}

// DeregisterRequest ends an exec and scrubs its rendered bytes. The token must match.
type DeregisterRequest struct {
	ExecID string `json:"exec_id"`
	Token  string `json:"token"`
}

// Response is the provider's reply to either request.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Status fields (populated only for an OpStatus reply).
	Active int    `json:"active,omitempty"` // number of projected execs
	Driver string `json:"driver,omitempty"` // backing FUSE driver name
}

// Control ops carried by a ControlRequest envelope (one JSON object per connection).
const (
	OpRegister   = "register"
	OpDeregister = "deregister"
	OpStatus     = "status"
)

// ControlRequest is the single message the client sends on a control connection. Op
// selects which payload is present.
type ControlRequest struct {
	Op         string             `json:"op"`
	Register   *RegisterRequest   `json:"register,omitempty"`
	Deregister *DeregisterRequest `json:"deregister,omitempty"`
}

// tokenBytes is the size of a one-time token before base64 (256 bits).
const tokenBytes = 32

// NewToken returns a fresh URL-safe one-time token bound to a single registration.
func NewToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Validate rejects a malformed registration before it reaches the provider's state.
// It enforces the invariants the security model depends on: a non-empty exec id and
// token, a positive root pid, an absolute backing root, and at least one ref-file with
// an absolute path that lies under the backing root (so a client can never register a
// rendered view for a file outside the project it owns).
func (r RegisterRequest) Validate() error {
	switch {
	case r.ExecID == "":
		return fmt.Errorf("empty exec_id")
	case r.Token == "":
		return fmt.Errorf("empty token")
	case r.RootPID <= 0:
		return fmt.Errorf("invalid root_pid %d", r.RootPID)
	case !filepath.IsAbs(r.Root):
		return fmt.Errorf("root must be absolute: %q", r.Root)
	case len(r.Files) == 0:
		return fmt.Errorf("no files to render")
	}
	root := filepath.Clean(r.Root)
	for _, f := range r.Files {
		if !filepath.IsAbs(f.Path) {
			return fmt.Errorf("file path must be absolute: %q", f.Path)
		}
		clean := filepath.Clean(f.Path)
		rel, err := filepath.Rel(root, clean)
		if err != nil || rel == ".." || hasDotDotPrefix(rel) {
			return fmt.Errorf("file %q escapes backing root %q", f.Path, root)
		}
	}
	return nil
}

// hasDotDotPrefix reports whether rel begins with a parent-dir hop ("../"), i.e. the
// target sits outside the root it was made relative to.
func hasDotDotPrefix(rel string) bool {
	return rel == ".." || (len(rel) >= 3 && rel[0] == '.' && rel[1] == '.' && (rel[2] == filepath.Separator))
}

// renderedMap projects the request's files into the registry's path→bytes form.
func (r RegisterRequest) renderedMap() map[string][]byte {
	m := make(map[string][]byte, len(r.Files))
	for _, f := range r.Files {
		m[filepath.Clean(f.Path)] = f.Content
	}
	return m
}

// Apply registers the request into reg using oracle as the subtree decider. The caller
// (the provider) builds an OS-specific oracle around RootPID first. Validate must have
// passed.
func (r RegisterRequest) Apply(reg *Registry, oracle SubtreeOracle) {
	reg.Register(r.ExecID, r.Root, r.Mountpoint, r.renderedMap(), oracle, r.Token)
}

// Encode/Decode are the line framing helpers used by both transports (one JSON object
// per message). They keep marshaling in one place so the client and service agree.
func Encode(v any) ([]byte, error) { return json.Marshal(v) }
func Decode(b []byte, v any) error { return json.Unmarshal(b, v) }
