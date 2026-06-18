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
   **RESULT (resolved 2026-06): WinFsp does NOT expose the caller PID during `Read`** — it
   only populates `fuse_context.pid` for `Create`/`Open`/`Rename` (a Windows limitation:
   the cache manager decouples reads from the originating process; sources: winfsp/winfsp
   #99, release notes v1.2POST1, `fuse_intf.c` `fsp_fuse_op_enter/leave`). So calling
   `fuse.Getcontext()` inside `Read` returns `-1`. **`FspFileSystemOperationProcessId()`
   does NOT help** — it reads the same request-token PID that is absent during `Read`.
   The implemented fix (the maintainer's recommended pattern) is to **capture the PID in
   `Open`/`Create` (where it is valid) and key it to the returned file handle (`fh`)**;
   `Read` and the post-open `Getattr` then resolve the caller by `fh`. See
   `provider_fuse.go` (`openHandle`/`callerPID`) and `provider_fuse_windows.go`.
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
  (darwin/windows/linux × amd64/arm64, default tags).
- **Verified (Windows host, 2026-06 — Windows Server 2025, Go 1.26, WinFsp 2.x):**
  `-tags sandboxdlp` compiles (cgofuse v1.6.0 + WinFsp FUSE headers); the per-process
  property holds end to end — `TestWinFuse_PerProcessGating` and
  `TestWinFuse_MountsAndNeverWritesDisk` pass, including `-race`; `sandbox-dlp serve` +
  `secrets-guard dlp-status` over the owner-only named pipe; the installer
  (`-ExePath` local build, Run-key fallback when not elevated); and a real-binary E2E
  (`secrets-guard sandbox -- node …` with a mock `op`): the in-subtree reader saw the
  rendered value, an unrelated process reading the same mounted `.env` saw only the
  `op://` reference, and the on-disk file never changed.
- **Windows adjustments made (see "Windows implementation notes" below):** PID captured at
  `Open` keyed by `fh` (not `FspFileSystemOperationProcessId`); `-o direct_io` added; mount
  made synchronous (register blocks until the volume serves); ancestry-walk oracle replaced
  by a Job Object + `IsProcessInJob`.
- **Pending / out of scope this pass:** Authenticode-signed binaries + a signed MSI (the
  installer ships unsigned with the signing steps TODO'd); running through an actual
  `claude -p` (the hook reduces to the same `secrets-guard sandbox -- …` invocation that
  the E2E exercises directly).

## Windows implementation notes (as built, 2026-06)

- **Caller PID by file handle.** `projFS` keeps an `fh -> pid` table; `Open`/`Create`/
  `Opendir` capture `fuse.Getcontext()`'s pid (valid there on WinFsp) and key it to a real
  handle; `Read` and the post-open `Getattr` resolve the caller via `callerPID(fh)`.
  `callerPID` is per-OS: Windows reads the handle's stored pid (fail-closed to `-1` for an
  unknown handle), darwin keeps the validated live-`Getcontext` path. This is why
  `FspFileSystemOperationProcessId()` was NOT wired in — it carries the same token PID that
  WinFsp omits during `Read`.
- **Caching / per-read gating.** `fuseMountOpts` uses `*Timeout=0` (no metadata cache).
  `-o direct_io` was tried but removed: it disables the cache Windows needs to memory-map
  image sections, so DLL / native-addon (`.node`) loads from the mount fail with
  ACCESS_DENIED and real toolchains (Next.js/SWC) can't run. The per-read gate holds anyway
  because the read handler resolves the caller per file-handle on every read (validated by
  the per-process test, run repeatedly with no cross-process leak).
- **Drive-letter mountpoint.** The client mounts on an unused drive letter (e.g. `Z:`), not
  a temp directory: a directory mount is a reparse point and Windows refuses to memory-map
  image sections from it (native modules fail to load), whereas a drive volume works. See
  `dlp_mount_windows.go`.
- **Real toolchains run under the mount.** The projection is a read-write loopback: writes
  to ordinary files pass through to the backing (errno-accurate), so `next dev` etc. work;
  writes/renames/removes of a declared ref-file are refused so the rendered value can never
  be persisted and the reference file is never modified through the mount.

## Credential isolation (Windows) — only the service can reach the vault

The point of the sandbox is defeated if any process can resolve secrets directly (a bare
`ksm secret notation …` / `op read …`). Two layers keep the vault reachable ONLY through
the plugin, configured automatically with no manual step:

- **The service is the sole credential holder.** Resolution moved from the client to the
  `sandbox-dlp` service: the client (`dlpRender`) sends only the ref-file PATHS; the service
  reads each backing file, resolves its references with its OWN credential, and serves the
  rendered bytes solely to the command's subtree — the plaintext value is produced only
  inside the service and never travels back over the control channel. The client holds no
  credential and never resolves on the Windows kernel-DLP path.
- **Auto-ingest + global-profile removal.** On startup the service provisions `KSM_CONFIG`
  into its OWN process environment (private to the process) from, in order: an externally
  provided `KSM_CONFIG` (MDM), its DPAPI-encrypted store, or a one-time export of the local
  `ksm` profile. After verifying the credential resolves and persisting a user-DPAPI-
  encrypted copy, it DELETES the global `ksm` profile from the OS Credential Manager (the
  delete must run with `KSM_CONFIG` unset, or `ksm` operates on the env config and the
  keyring profile survives). A bare `ksm` by any other process — including the agent — then
  fails ("Keeper SDK client has not been loaded"). See `credential_windows.go`.
- **Hook denial (defense in depth).** The plugin's `PreToolUse` hook denies any Bash command
  that invokes a vault CLI (`ksm`/`keeper`/`op`) or `secrets-guard read|run` directly, so
  the model is told to use a reference and let the sandbox render it.
- **Residual (same-user, by design choice).** The service runs as the user, so its DPAPI
  store is decryptable by a determined same-user process; the chosen level removes the easy
  global profile and the agent's direct-CLI path. A separate low-privilege service account
  would close the same-user residual.
- **Synchronous mount.** `fuseMounter.Mount` now blocks (`waitMountReady`) until the
  mountpoint answers a directory listing before returning, so a client that `chdir`s into
  the mountpoint right after a successful `Register` never races the async WinFsp mount.
- **Job Object oracle.** `oracle_windows.go` creates a Job Object per exec, assigns the
  root PID before the command is spawned (descendants inherit the job), and answers
  membership with `IsProcessInJob` (race-free, no PID reuse). `IsProcessInJob` is not in
  `golang.org/x/sys/windows`, so it is bound from `kernel32.dll` directly. The job handle
  is released on deregister (`service.go` `closeOracle`). The ancestry walk
  (`CreateToolhelp32Snapshot`) remains as a fail-safe fallback if the job can't be created.
- **Build toolchain.** cgofuse's Windows cgo needs WinFsp's FUSE headers
  (`<fuse.h>`/`<fuse_common.h>`/`<fuse_opt.h>` + `<winfsp/winfsp.h>`). The winget WinFsp
  package ships only the runtime; obtain the headers via an MSI admin-extract
  (`msiexec /a winfsp.msi TARGETDIR=<dir>`) and build with
  `CGO_CFLAGS=-I<dir>\inc\fuse -I<dir>\inc` (CGO_ENABLED=1, mingw-w64 gcc on PATH).
- **Installer autostart.** A logon Scheduled Task needs elevation; the installer falls back
  to a per-user `HKCU\…\Run` entry (no elevation) for the autostart, and starts the service
  immediately. WinFsp's own install still requires elevation (kernel driver). Binaries and
  the script are unsigned for now (signing is TODO'd in the script).

## Proactive redaction guard (service-side, Windows)

The sandbox stops a value from being *written to disk*; the redaction guard stops a value
from *reaching the model* — even one that was never referenced this session (e.g. a
hardcoded secret the agent tries to `Read`). On macOS/Linux the per-session in-memory cache
(`internal/cache`, a 0700 unix-socket daemon) holds the resolved values and the hook scans
tool I/O against them. That cache does not apply on Windows (its unix ownership/permission
model rejects the socket dir), and the client holds no credential, so the guard runs **in
the service**:

- The hook routes every scan through the control channel: `OpScan{text}` → the service
  redacts `text` against EVERY value its credential can read and returns only the
  already-redacted text + a `found` flag. The matched VALUES never cross the wire.
- The service keeps those values in its own RAM (`valueGuardStore`, refreshed on a short
  TTL via `vault.AllSecretValues`, invalidated on `create`), so the credential and the
  values stay inside the service exactly as for file rendering.
- The client selects the guard with `valueGuard(cfg)`: `serviceCache` (→ `OpScan`) on the
  Windows kernel-DLP path, the local in-memory cache otherwise. The hook's `UserPromptSubmit`
  / `PreToolUse` / `PostToolUse` paths and `redact-stream` all go through it, so a prompt,
  tool input, tool output, or file read carrying a vault value is blocked or redacted.
- Toggle with `PRELOAD_SECRETS` (`auto`|`on`|`off`); `off` limits the guard to
  session-resolved values. `vault.AllSecretValues` collects field/custom/notes values only
  (never titles/labels/UIDs) and drops values shorter than 6 bytes to avoid pathological
  over-redaction of short common strings.

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
