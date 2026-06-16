# sandbox-dlp — kernel-level DLP for secrets-guard (architecture & Windows handoff)

This document is the map for finishing the **Windows** kernel-DLP provider. macOS and
Linux are already settled (see "Per-OS strategy"). Read this top to bottom before
touching code; the empirical findings below are the reason the design is what it is.

## Goal

When secrets-guard renders a vault reference (`op://…`, `keeper://…`) into a real secret
**value** so an app can read it from a config file, we want, on every platform:

1. **Per-process:** only the secrets-guard command's process subtree sees the value;
   every other process reading the same path sees the original **references**.
2. **Never on disk:** the real file keeps the references the whole time; the value lives
   only in RAM.

## Per-OS strategy (and why)

| OS | Mechanism | Per-process | Value on disk | Status |
|----|-----------|-------------|---------------|--------|
| **Linux** (Cowork VM + hosts) | private `mount --bind` of a rendered tmpfs copy inside an unprivileged user+mount namespace | yes | never | **done** (gold standard) |
| **macOS** | in-place render of the real file + restore + crash-recovery journal | no (all processes see it during the command) | briefly | **done** (v0.4.2) — see below |
| **Windows** | `sandbox-dlp` service: a **WinFsp** user-mode provider that serves rendered bytes to only the subtree | **yes** | **never** | **provider written, needs Windows to compile/test** |

**Why macOS can't do better without a kext (measured, 2026-06):** every kext-free
per-process file-content mechanism on macOS is defeated by SIP.
- fuse-t (FUSE over NFS): the read handler's caller pid is always **0** (NFS carries no
  pid) → per-process impossible.
- FSKit (native, macOS 15+): the read API (`readFromFile:offset:length:intoBuffer:`)
  exposes **no caller identity** at all (checked the whole SDK).
- EndpointSecurity: can only authorize/deny opens, **cannot rewrite** read buffers.
- DYLD interposition (`DYLD_INSERT_LIBRARIES`): works for a directly-exec'd non-hardened
  app (proven with node), but **SIP strips it through every system shell/binary**
  (`/bin/sh`, `/bin/zsh`, `/bin/cat`, system python) and through nested shells — and the
  hook wraps commands in `sh -c`, so it doesn't survive to the app. Too fragile.
- The only robust macOS mechanism is **macFUSE (a kext)**, which on Apple Silicon needs a
  reduced-security/Recovery install we can't ask end users to do.

→ macOS keeps the in-place renderer. **Windows is where the user-mode-provider design
actually delivers the full property**, because WinFsp is a signed driver (MSI install, no
Secure-Boot dance) that **reports the requesting process id** to the file system.

## Components

```
internal/projection/   the OS-independent security core (fully unit-tested)
  registry.go          per-exec map: ref-file path -> rendered bytes, gated by a
                       SubtreeOracle; Resolve(path,pid) decides serve-rendered vs
                       pass-through; fail-closed; scrubs RAM on Deregister.
  protocol.go          control wire types (RegisterRequest/DeregisterRequest/
                       ControlRequest/Response), NewToken(), Validate() (rejects files
                       outside the project root).

internal/dlpipc/       local control transport (client + endpoint), shared by the CLI
                       and the service.
  dial.go              Call(req)->Response, Healthy().
  endpoint_unix.go     unix socket in a per-user 0700 dir (macOS/Linux).
  endpoint_windows.go  named pipe \\.\pipe\secrets-guard-dlp-<SID> (go-winio).

cmd/sandbox-dlp/       the per-user service (Windows target; darwin files are dev-only).
  service.go           Service: handleRegister (mount + register), handleDeregister
                       (scrub + unmount), dispatchControl. Portable.
  provider_fuse.go     SHARED FUSE provider (darwin||windows, tag `sandboxdlp`):
                       loopback over the backing project + per-process override of
                       declared ref-files via reg.Resolve(fuse.Getcontext pid).
  provider_fuse_windows.go  WinFsp specifics: driver name, mount opts (caching off),
                       mountpoint prep. **The Windows work lives here + the test.**
  provider_fuse_darwin.go   macFUSE specifics (dev / optional full-coverage mode).
  oracle_windows.go    SubtreeOracle via CreateToolhelp32Snapshot ancestry walk.
  oracle_darwin.go     SubtreeOracle via sysctl(kern.proc.pid) ancestry walk.
  ipc_windows.go       named-pipe control server (owner-only SDDL), runServe/runStatus.
  ipc_darwin.go        unix-socket control server (peer-cred), runServe/runStatus.
  provider_nofuse.go   fail-closed mounter when built without the `sandboxdlp` tag.
  main.go              `sandbox-dlp {serve|status}`.

cmd/secrets-guard/     the plugin CLI (client side).
  dlp.go               kernelDLPActive (Windows-only) + dlpRender: resolve refs ->
                       rendered bytes -> register with the service -> run the command
                       with cwd = mountpoint -> deregister.
  dlp_install.go       dlp-status / dlp-install + SessionStart maybeTriggerDLPInstall.
  sandbox.go           renderAndExec: chooses DLP vs in-place; threads child cwd.
```

## End-to-end flow (Windows)

1. The hook wraps a Bash command as `secrets-guard sandbox -- sh -c '<original>'`.
2. `secrets-guard sandbox` resolves the references it finds (env, command, ref-files) with
   the local vault, then for files calls `dlpRender` (kernelDLPActive == true on Windows):
   - computes the rendered bytes for each ref-file (escape-aware),
   - creates a per-exec mountpoint (temp dir) and a one-time token,
   - `RegisterRequest{ ExecID, Root=cwd, Mountpoint, Files=[{path,renderedBytes}],
     RootPID=os.Getpid(), Token }` → `dlpipc.Call` over the named pipe.
3. The service (`handleRegister`) mounts a WinFsp projection of `Root` at `Mountpoint`,
   builds a `subtreeOracle{root: RootPID}`, and registers the rendered map.
4. `secrets-guard` runs the command with **cwd = Mountpoint**. Its reads of `.env` etc.
   hit the provider; the provider asks `reg.Resolve(path, callerPid)`:
   - caller in the RootPID subtree → **rendered bytes** (from RAM),
   - anyone else → pass-through to the real backing (**references**).
5. On exit (or signal), `secrets-guard` deregisters (scrub + unmount). The real file was
   never written; the value never hit disk.

The authorized identity is the **process subtree** rooted at the secrets-guard sandbox
process (`RootPID = os.Getpid()`); the command it spawns and that command's descendants
are in the subtree.

## Finishing on Windows — step by step

1. **Toolchain:** install WinFsp (https://winfsp.dev) + a cgo gcc (mingw-w64 via
   msys2/scoop, or TDM-GCC). `CGO_ENABLED=1`, gcc on PATH.
2. **Build:** `go build -tags sandboxdlp ./cmd/sandbox-dlp` and
   `go build -tags sandboxdlp ./cmd/secrets-guard` (the secrets-guard client never needs
   the tag; only sandbox-dlp does). Fix any cgofuse/WinFsp signature mismatches in
   `provider_fuse_windows.go` / `provider_fuse.go`.
3. **VERIFY THE PID (make-or-break):** run
   `go test -tags sandboxdlp -run TestWinFuse_PerProcessGating ./cmd/sandbox-dlp/`.
   - If it passes: per-process works through `fuse.Getcontext()`. Done with the core.
   - If the test `Skip`s with "driver did not expose caller PID": cgofuse isn't surfacing
     the WinFsp process id. Wire the oracle to **`FspFileSystemOperationProcessId()`**
     (WinFsp's authoritative source). Smallest change: add a hook in the provider's read
     path that reads it from the WinFsp host and pass that pid to `reg.Resolve` instead of
     `fuse.Getcontext()`'s pid.
4. **Mount options:** confirm caching is actually off (`FileInfoTimeout=0` etc. in
   `fuseMountOpts`). If repeated reads return stale content for the wrong process, caching
   is the cause. If directory mounts misbehave, switch to a drive-letter mountpoint (have
   the client pass e.g. an unused letter; drop the remove in `prepareMountpoint`).
5. **Service IPC:** `sandbox-dlp serve` should host the named pipe with the owner-only
   SDDL (`ipc_windows.go`); `secrets-guard dlp-status` should report it. The pipe ACL is
   the auth boundary (Windows analogue of unix peer-cred).
6. **Hardening (after it works):** replace the ancestry-walk oracle with a **Job Object**
   the service creates per exec + `IsProcessInJob` (race-free, no PID reuse). The client
   would need to assign the command to that job, or the service creates the job and the
   client registers the root pid for the service to AssignProcessToJobObject.
7. **Installer:** finish `installers/windows/sandbox-dlp-setup.ps1` (pin + verify WinFsp,
   ship the signed sandbox-dlp.exe, register the logon task). Ideally replace with a
   signed MSI. Wire the real asset URLs into `dlp_install.go` (`defaultDLPBase`).
8. **End-to-end:** with the service running, run a real `claude -p` whose command reads a
   `.env` (e.g. `node -e "...readFileSync('.env')"`); from a second terminal `type` the
   same file concurrently — it must show only `op://…`; after the command, the file on
   disk is unchanged and no value is anywhere on disk.

## What's verified vs pending

- **Verified (this repo, macOS dev host):** projection core (`go test -race`), protocol,
  IPC client/server (darwin), client wiring (`dlp_test.go`), the darwin FUSE provider
  *mounts and never writes disk* (via fuse-t), full cross-compilation
  (darwin/windows/linux × amd64/arm64, default tags). The per-process property was
  validated on macFUSE-class semantics; fuse-t can't show it (pid 0) but proves the mount
  + never-on-disk mechanics.
- **Pending (needs a Windows host):** compiling `-tags sandboxdlp` on Windows, the
  `fuse.Getcontext()` pid verification, mount-option tuning, the installer, and the real
  end-to-end. None of this is verifiable from macOS (cgo can't cross-compile to Windows,
  and WinFsp is Windows-only).

## Security model & residuals

- Confidentiality on Windows: the rendered value lives only in the per-user service's RAM
  and the authorized child's memory; the backing file keeps references; fail-closed
  everywhere (missing driver, failed mount, unknown caller → serve references).
- Irreducible residual: a process the agent's own command legitimately spawns is in the
  subtree and gets the value ("in the subtree = the agent"), same spirit as Linux's
  "in the VM = the agent". A debugger inside the subtree can read the child's memory.
- The control channel carries rendered bytes from the per-user CLI to the per-user
  service (same trust domain); values are never returned over it — only served to a
  subtree-gated read.
