package main

// Client side of the kernel-level DLP path (macOS/Windows). When the sandbox-dlp
// service is installed and healthy, file rendering goes through it instead of the
// in-place renderer: secrets-guard resolves the references, hands the *rendered* file
// content to the service over the authenticated local channel, and runs the command
// with its working directory inside the service's per-exec mount. The service serves the
// rendered bytes only to this process's subtree; the real disk keeps only references and
// the value never touches disk. On exit (or signal) the exec is deregistered and the
// mount torn down.

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/dlpipc"
	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// kernelDLPActive reports whether file rendering should be routed through the
// sandbox-dlp service. This is WINDOWS-ONLY: WinFsp propagates the requesting process
// id to its read handler, so the service can serve the rendered value to only the
// command's subtree and keep it off disk.
//
// It deliberately excludes macOS and Linux:
//   - Linux already isolates files with a private bind-mount inside a mount namespace.
//   - macOS has no robust kext-free way to substitute file content per process: SIP
//     strips DYLD_INSERT_LIBRARIES through every system shell/binary in the chain
//     (measured), fuse-t reports caller pid 0, and FSKit exposes no caller identity.
//     macOS therefore keeps the in-place renderer (renderFiles in
//     sandbox_render_other.go) with its restore + crash-recovery journal.
func kernelDLPActive(cfg config.Config) bool {
	if cfg.KernelDLP == "off" || cfg.IsCowork {
		return false
	}
	return runtime.GOOS == "windows"
}

// shortTmp returns a base temp dir with a short path (mount/socket paths have OS length
// limits, and macOS's default TMPDIR under /var/folders is long).
func shortTmp() string {
	if runtime.GOOS == "windows" {
		return os.TempDir()
	}
	return "/tmp"
}

// dlpRender registers the rendered ref-files with the sandbox-dlp service and returns the
// per-exec mountpoint to run the command in, plus a deregister/cleanup function. ok is
// false when the service is unavailable or rejects the registration; the caller then
// decides the fallback (fail-closed for kernel_dlp=require, in-place for auto).
func dlpRender(files []refFile, values map[string]string) (mountpoint string, deregister func(), ok bool) {
	if !dlpipc.Healthy() {
		return "", nil, false
	}
	// Compute the rendered content for each ref-file (escape-aware). Files with no
	// resolvable reference right now are left out (served straight from the backing).
	var rf []projection.RenderedFile
	for _, f := range files {
		orig, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		rendered := renderRefs(string(orig), values)
		if rendered == string(orig) {
			continue
		}
		abs, err := filepath.Abs(f.path)
		if err != nil {
			continue
		}
		rf = append(rf, projection.RenderedFile{Path: abs, Content: []byte(rendered)})
	}
	if len(rf) == 0 {
		return "", nil, false
	}

	mountTarget, mp, mpCleanup, err := chooseMountpoint()
	if err != nil {
		return "", nil, false
	}
	token, err := projection.NewToken()
	if err != nil {
		mpCleanup()
		return "", nil, false
	}
	execID, err := projection.NewToken()
	if err != nil {
		mpCleanup()
		return "", nil, false
	}

	req := projection.RegisterRequest{
		ExecID:     execID,
		Root:       cwd(),
		Mountpoint: mountTarget,
		Files:      rf,
		RootPID:    os.Getpid(), // this process + the command it spawns = the authorized subtree
		Token:      token,
		TTLSeconds: 3600,
	}
	resp, err := dlpipc.Call(projection.ControlRequest{Op: projection.OpRegister, Register: &req})
	if err != nil || !resp.OK {
		mpCleanup()
		return "", nil, false
	}

	deregister = func() {
		_, _ = dlpipc.Call(projection.ControlRequest{
			Op:         projection.OpDeregister,
			Deregister: &projection.DeregisterRequest{ExecID: execID, Token: token},
		})
		mpCleanup()
	}
	return mp, deregister, true
}
