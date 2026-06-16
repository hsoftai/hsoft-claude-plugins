//go:build !(sandboxdlp && (darwin || windows))

package main

import (
	"fmt"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// nofuseMounter is the default mounter when the binary is built WITHOUT the
// `sandboxdlp` build tag (i.e. without the cgofuse/macFUSE/WinFsp dependency). It
// errors on Mount, so a service built this way can run its control plane but cannot
// project files — exactly the fail-closed posture we want until the real driver-backed
// build is produced. Build the real provider with: go build -tags sandboxdlp ./cmd/sandbox-dlp
type nofuseMounter struct{}

func newMounter() mounter { return nofuseMounter{} }

func (nofuseMounter) Name() string { return "(none: built without -tags sandboxdlp)" }

func (nofuseMounter) Mount(execID, mountpoint, root string, _ *projection.Registry) (func() error, error) {
	return nil, fmt.Errorf("sandbox-dlp built without a FUSE provider (rebuild with -tags sandboxdlp and macFUSE/WinFsp installed)")
}
