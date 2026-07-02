# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.5] - 2026-07-02

### Changed
- **`secrets-guard install` is now fully self-healing — it fixes a stale, locked or dirty CLI
  on its own, with no manual commands.**
  - **Stale version:** `install` now sources the NEWEST binary available — the authoritative
    build bundled with the plugin, discovered via `CLAUDE_PLUGIN_ROOT` and the user's Claude
    plugins directory — instead of only re-copying the running process. So an out-of-date
    user-PATH CLI running `install` upgrades ITSELF from the plugin bundle, rather than copying
    its own old version back over itself (which left `doctor` reporting a version behind the
    plugin). A locally-built `dev` binary is never auto-downgraded.
  - **Version-aware copy:** the installer decides to re-copy by comparing the source and
    installed versions (authoritative), not just file size/mtime — two adjacent builds can share
    an identical size, which the old heuristic missed. Re-running `install` when already
    up to date does nothing (no churn).
  - **Locked binary:** if the target is busy (a running CLI holds the image locked, common on
    Windows), it is displaced to `<bin>.old` and the fresh binary is put in its place; the
    displaced copy is cleaned up on the next install. Also cleans leftover `<bin>.tmp`.
  - **Dirty cache:** `install` resets this session's in-memory cache daemon so the guard
    re-primes from the just-installed binary instead of a daemon still running old code.

## [0.8.4] - 2026-07-02

### Fixed
- **`secrets-guard install` no longer keeps a stale CLI when the binary is busy.** On Windows a
  loaded executable cannot be overwritten in place, so a previous session's running CLI made the
  self-install silently keep the old binary — `doctor` then reported a version behind the plugin
  (e.g. plugin 0.8.3 but `doctor` 0.8.2). The installer now displaces the locked binary to
  `<bin>.old` (Windows allows renaming a running image) and moves the fresh one into place, so the
  next launch runs the new version; the displaced copy is cleaned up on the following install.

### Added
- **Actionable hints for well-known Keeper failures in `doctor` and `install`.** When the vault
  can't be validated, the diagnostics now explain the exact fix instead of only echoing the raw
  error:
  - `This client is locked to a different ip address` → the Secrets Manager application/token is
    IP-locked and this machine's egress IP differs (VPN / corporate NAT / DHCP); turn OFF
    "Lock to IP Address", issue a new token, and re-run `secrets-guard install`.
  - `Unable to validate application access` → bind a Shared Folder (with at least one record) to
    the application and issue a new token.
  - no profile loaded → run `secrets-guard install` and paste a one-time token.

## [0.8.3] - 2026-07-02

### Fixed
- **The vault now keeps working in the VSCode terminal / extension, not just the Windows
  console — permanently.** Root cause (replicated): `keeper-ksm profile init` stores the
  profile in the Windows Credential Manager, which is NOT reliably readable from every process
  context (e.g. the VSCode-spawned hook). While the per-session cache was warm it worked, but
  after the cache's 30-minute idle timeout the re-prime needed the vault, couldn't read the
  Credential Manager there, and — under `guard_required=on` — failed closed with "DLP guard
  unavailable". (The Keeper one-time token does NOT expire; the profile is permanent — this was
  never a token issue.)
- **Self-healing managed config:** the SessionStart preload now refreshes the
  secrets-guard-managed `keeper.ini` (`%LOCALAPPDATA%\secrets-guard\keeper.ini`) from the active
  profile whenever the default resolution is reachable, so a portable, file-based config is
  always present. Combined with 0.8.2's default-first + `--ini-file` fallback, the vault then
  resolves deterministically from every terminal — even when the Credential Manager isn't
  readable. It never wipes an existing managed config when the default profile is momentarily
  unreachable.

## [0.8.2] - 2026-07-01

### Fixed
- **A stale or foreign `~/.keeper/keeper.ini` no longer shadows the working profile.**
  Supersedes 0.8.1's approach: 0.8.1 made the runner ALWAYS inject `--ini-file`,
  auto-discovering `~/.keeper/keeper.ini` — but an old config there (whose Keeper application
  had lost access) then made every secrets-guard `ksm` call fail with "access_denied /
  Unable to validate Keeper application access", even though the bare `keeper-ksm` CLI worked
  via the Windows Credential Manager profile. `secrets-guard install` then also failed to
  validate (and wasted the one-time token). Fixes:
  - Vault resolution now tries the **default profile (Windows Credential Manager) FIRST** and
    only falls back to a `--ini-file` config if the default fails (no more shadowing).
  - The plugin reads its config from a **fixed secrets-guard-managed location**
    (`%LOCALAPPDATA%\secrets-guard\keeper.ini`), not from `~/.keeper` — so a stray keeper.ini
    can never shadow it.
  - **`secrets-guard install` persists the config to that managed location** (via
    `ksm profile export`), so the vault resolves **deterministically from every terminal**
    (Windows console, VSCode, …) and working directory, independent of Credential Manager
    per-session readability.

## [0.8.1] - 2026-06-30

### Fixed
- Attempted to detect a `ksm profile init` profile from any directory by always injecting the
  global `--ini-file` flag (auto-discovering `~/.keeper/keeper.ini`). This caused a
  regression when a stale keeper.ini was present — see 0.8.2, which replaces this mechanism.

## [0.8.0] - 2026-06-27

Architecture simplification: two commands only (the hook-injected wrapper + the
model-facing `secrets-guard run`), no sandbox, inert in Cowork.

### Changed
- **Bash command references are now provisioned via the child ENVIRONMENT, not injected
  inline.** The hook replaces each reference with a `${SG_REF_n}` placeholder and wraps the
  command in `SG_REF_n='<ref>' secrets-guard run -- sh -c '<cmd>'`, which resolves the value
  into the child process environment. The plaintext value never enters the command text,
  argv, the shell, the transcript, or disk — so it no longer reaches Claude Code's permission
  classifier (which previously could echo an inline-injected value back into the model's
  context). Fixes the inline-injection credential-leak-to-classifier class of bug.
- **`secrets-guard run` is now allowed for the model** (e.g. `secrets-guard run --env-file
  .env -- <cmd>`): it injects resolved values only into the child environment and its output
  stays redacted, giving a functional path to run an app that needs real values from a `.env`
  with `SANDBOX` gone. `secrets-guard read` and the raw vault CLIs (ksm/op/keeper) remain
  denied (they print values to stdout).
- **PostToolUse blocks a confirmed vault-value leak** (already in 0.7.4) instead of relying on
  the unreliable `updatedToolOutput`.

### Added
- **Guided onboarding (`secrets-guard install`).** `install` now does the full setup
  interactively: it auto-detects and installs the Keeper Secrets Manager CLI if missing
  (winget on Windows, brew/pip elsewhere), prompts for a one-time token, runs
  `ksm profile init`, and validates the connection — leaving the guard fully active. With a
  vault already configured it just detects and validates it (no prompt).
- **`require_vault` onboarding gate (default `on`).** When no vault is configured at all, a
  prompt is BLOCKED with step-by-step Keeper setup instructions (create a Shared Folder, bind
  a Secrets Manager Application to it, get a one-time token, run `secrets-guard install`).
  Set `require_vault=off` to allow use without a vault (degrade to the pattern detector).
- **Reference parser robustness (A2):** a trailing unbalanced `]` is no longer swallowed into
  the reference (`keeper://UID/field/password]` resolves the clean reference and keeps the
  `]` literal); balanced Keeper `[index]` notation is preserved.
- **Per-reference fail policy (A3):** a single unresolvable reference no longer aborts the
  whole command — `secrets-guard run` resolves what it can and leaves the rest, degrading
  instead of failing closed on the entire command.

### Removed
- **The `sandbox` feature is gone** — the `sandbox` subcommand, in-place file rendering and
  crash-recovery journal, and the `sandbox`/`sandbox_globs`/`kernel_dlp`/`dlp_install_source`
  options. Reference provisioning is now exclusively env-injection via `secrets-guard run`.
- **secrets-guard is INERT in Cowork:** when running on a Cowork host the hook does not
  inspect, redact, deny, or rewrite anything (even if the plugin is installed and enabled).
  It operates only in Claude Code (local). Cowork value-delivery will be handled separately.

## [0.7.4] - 2026-06-27

### Fixed
- **`Read` of a file containing a vault secret is now blocked (it was leaking).** Claude Code
  2.1.x does not apply a PostToolUse `updatedToolOutput` to the `Read` tool's structured file
  content, so the in-place redaction never took effect and the secret reached the model —
  even though detection was correct. There is no command to wrap at the source as there is
  for Bash. The guard now inspects the target file at **PreToolUse** and DENIES the read
  before it runs when the file contains a vault value (in any encoding); the content is never
  produced. Files without a vault value read normally. Runs only when a vault is configured.
  Trade-off: the whole read is blocked (Read cannot be partially redacted), so use the vault
  reference (keeper://… / op://…) instead of the literal value.

### Changed
- **PostToolUse now BLOCKS a confirmed vault-value leak instead of redacting in place.**
  Because `updatedToolOutput` is not reliably honored by Claude Code (ignored for Read,
  unconfirmed for others), a redacted string could silently fail to apply. When the guard
  finds a known vault value in a tool output it now returns `decision: "block"` (the
  CC-sanctioned suppression). Detector-matched (non-vault) secrets still follow
  `tool_output_mode` (redact/block/off).

## [0.7.3] - 2026-06-27

### Changed
- **Corrected stale option descriptions that referenced the removed `sandbox-dlp` service.**
  The `preload_secrets` and `guard_required` settings (and their config comments) still said
  the Windows credential holder was the `sandbox-dlp` service and that the guard degrades
  when that service is "unreachable." That service was removed in 0.6.0: on every platform,
  Windows included, the vault values live in the per-session in-memory cache loaded from the
  user's own local ksm/op profile — there is no service to install or reach. The descriptions
  now reflect the local model, so a misconfiguration (e.g. `preload_secrets=off` or an
  uninitialized profile) is no longer misdiagnosed as a missing service. `dlp_install_source`
  and `kernel_dlp` are documented as deprecated no-ops.

### Removed
- Dead code: `ExportKeeperConfig`, `DeleteKeeperProfile`, `VerifyKeeperConfig` (part of the
  old service's credential-handoff flow; unused since the local model).

## [0.7.2] - 2026-06-27

### Fixed
- **Login-type secrets are now redacted.** The full-vault preload runs `ksm secret get`,
  which **masks** password-like fields by default (returns `******` instead of the value).
  The redaction guard was therefore caching the mask, not the real password, so a login
  record's password was never censored when it later appeared in a file/tool output — while
  non-masked fields (text/custom secrets) still were. The preload now passes `--unmask`, so
  every real value enters the guard. (Usernames/emails/urls remain excluded and visible.)

### Added
- **`secrets-guard doctor` now warns when `preload_secrets=off` but the vault is reachable.**
  In that state the full-vault redaction guard is disabled, so a file/tool read of a vault
  secret that was not resolved this session is neither redacted nor blocked. The diagnostic
  calls it out explicitly and points to `CLAUDE_PLUGIN_OPTION_PRELOAD_SECRETS=auto`.

## [0.7.1] - 2026-06-26

### Fixed
- **Detect the Keeper CLI when it is installed as `keeper-ksm.exe`.** The standalone Keeper
  release ships the binary as `keeper-ksm` (only the pip console script is named `ksm`), so a
  host with just `keeper-ksm.exe` on PATH reported "vault: none" despite a working CLI.
  secrets-guard now resolves either name (`ksm` or `keeper-ksm`) everywhere it invokes Keeper
  — availability, reference resolution, the full-vault preload, and the PATH/diagnostic
  checks — so the vault is found regardless of which package provided the CLI.
- **Find the Keeper config even when it lives in a per-user folder.** ksm only looks for
  `keeper.ini` in the CURRENT directory by default, so a profile initialized to
  `~/.keeper/keeper.ini` (or via `ksm profile init --ini-file ...`) was invisible when ksm
  ran from a project directory — the SDK reported "The Keeper SDK client has not been
  loaded. The INI config might not be set," the vault stayed unreachable, the value cache
  stayed empty, and file reads were therefore NOT redacted. secrets-guard now detects a
  `keeper.ini` in `~/.keeper/` or `~/` (sets `KSM_INI_FILE`) and passes ksm the global
  `--ini-file` flag, so the user's profile loads regardless of the working directory.
  An explicit `KSM_CONFIG` (base64) or `KSM_INI_FILE` is respected as-is.

### Added
- **`guard_required=on` now blocks a tool output when the vault is configured but its values
  could not be loaded** ("if a redact is not possible, block the read"). When a vault is
  selected yet its value cache could not be primed (e.g. a broken ksm/op profile), the guard
  cannot prove a tool result is free of vault secrets, so under the strict fail-closed policy
  it blocks the result instead of risking a plaintext leak. The default `guard_required=auto`
  is unchanged: it degrades to the built-in detector instead of blocking, so a machine whose
  vault is momentarily unavailable is never bricked.

## [0.7.0] - 2026-06-26

### Changed
- **Tool output is now REDACTED IN PLACE, not blocked.** When a tool result (e.g. a `Read`
  of a file) contains a vault value or a detected secret, the model now receives the output
  with the secret replaced by the placeholder (`updatedToolOutput`) instead of the whole
  result being withheld. The original stays in the transcript. `tool_output_mode=block`
  still withholds; `redact` (default) censors in place.
- **For login records, only the password is redacted — the username stays visible.** The
  guard no longer loads username/email/url fields (Keeper `login`/`email`/`url` types, or
  1Password `USERNAME` purpose) into the redaction set, so reading a file that has both a
  username and a password censors only the password.

### Fixed
- **Consistent detection.** Redaction depended on an async SessionStart preload populating
  the per-session cache, which could lose the race or expire — so detection was
  intermittent. The hook now guarantees the cache is primed before scanning any prompt or
  tool I/O: it loads the full vault synchronously on the first scanning event if not already
  primed (then it is cached for the session). Every Read/tool output is now always scanned
  against every vault value.

## [0.6.4] - 2026-06-26

### Fixed
- The Keeper CLI (`ksm`, shipped as `ksm.bat`) is now found even when the host spawns the
  hook with a thin/empty `PATHEXT` — observed with the VSCode Claude extension host, where
  the terminal CLI detected the vault but the extension reported it as `none`. The PATH
  augmentation now also normalizes `PATHEXT` to include `.BAT`/`.CMD` so `exec.LookPath`
  resolves a `.bat`/`.cmd` CLI regardless of the inherited environment.

## [0.6.3] - 2026-06-26

### Fixed
- The vault CLI is now found even under a stale launch PATH. secrets-guard detects the vault
  with a PATH lookup; if the Claude Code process inherited a PATH from before the Keeper/1Password
  CLI was installed (common on Windows for a long-running GUI app), the CLI was not found and the
  vault reported `none`, degrading to the detector even with a configured profile. The client now
  augments its PATH from the machine + user registry `Path` (env vars expanded) when the CLI is
  not already resolvable — restoring the same behavior the removed service used to have.

## [0.6.2] - 2026-06-26

### Changed
- SessionStart now self-heals: besides installing the CLI on PATH and preloading the vault
  cache, it silently removes any leftover components from the old WinFsp/service model
  (detected cheaply by stat, removed only when present). So changing a managed-settings
  option (e.g. `PRELOAD_SECRETS`/`SANDBOX` off→on) or transitioning a dirty machine is
  picked up automatically on the next session with no manual `install` — plugin options are
  read fresh every hook invocation. The only per-user prerequisite that is not auto-
  provisioned is the vault profile (`ksm profile init`); without it the guard degrades to
  the pattern detector.

## [0.6.1] - 2026-06-26

### Fixed
- Documentation/skill consistency for the local model: the `using-vault-secrets` skill no
  longer references a credential-holding service ("only the service holds the credential",
  "the client has no credential") — the MCP tools read the user's local vault directly and
  return metadata/references only.

## [0.6.0] - 2026-06-25

### Removed
- **Removed the Windows kernel-DLP path entirely: no more WinFsp driver and no more
  `sandbox-dlp` system service.** The `installers/windows/sandbox-dlp-setup.ps1` script and
  `docs/sandbox-dlp.md` are deleted, and secrets-guard no longer requires administrator
  rights or installs anything machine-wide. The `kernel_dlp` option is **deprecated and a
  no-op** (ignored if present).

### Changed
- **secrets-guard now runs entirely per-user (local model).** The redaction guard reads the
  user's own vault through their local `ksm` / `op` profile (in its default location — the
  profile is not moved, deleted, or DPAPI-protected), loads every value into a per-session
  **in-memory cache** at session start, and redacts/blocks those values (in any encoding) in
  prompts and tool input/output before they reach the model. If the vault profile isn't
  initialized, the guard degrades to the built-in secret-pattern detector and never blocks
  normal use. The per-session in-memory cache that backs the proactive full-vault guard now
  works on **Windows** too (previously the value store lived in the Windows service).
- **`dlp-install`, `doctor`, and `dlp-status` are now local** — they install/clean up the
  per-user CLI footprint and report the local vault/guard state, with no service to query.

### Added
- **`secrets-guard install` is now a descriptive, idempotent installer.** It installs the
  CLI on PATH, cleans up any legacy components (the old service/driver footprint), checks the
  vault, warms the in-memory cache, and reports clearly with clean/dirty detection. Re-running
  is safe.
- **`secrets-guard uninstall`** removes the full per-user secrets-guard footprint (no admin).
- **`GUARD_REQUIRED`** option (`auto` | `on` | `off`, default `auto`) — fail-closed policy
  when the local vault is unavailable: `auto` degrades to the pattern detector, `on` fails
  closed, `off` never fails closed.

## [0.4.2] - 2026-06-15

### Changed
- **The rendering sandbox now runs on macOS and Windows too, not just Linux.** Linux
  keeps the private bind-mount (the value never touches the real disk). macOS/Windows
  render the matched files **in place** with the real values, run the command, and
  restore the original references immediately after — guarded by a crash-recovery
  journal (it stores the originals, i.e. references, not values) that SessionStart
  replays if a command was hard-killed mid-render, plus signal handlers for clean
  interruption. The sandbox also redacts the command's stdout/stderr **inline** now
  (a printed value is masked, not just blocked). `sandbox` defaults to `auto` (on
  wherever a vault resolves), so the protection — env + file + command rendering and
  output redaction — is uniform across Linux, macOS and Windows.

## [0.4.1] - 2026-06-15

### Fixed
- **Cowork: the protection now applies to the MCP shell tool.** In Cowork the agent
  runs shell commands through `mcp__workspace__bash`, not the `Bash` tool. The hook
  matched `tool_name == "Bash"` exactly, so it **ignored** Cowork's shell tool —
  references passed through unrendered and unredacted. The hook now treats any
  command-execution shell tool as such: `Bash`, a bare `bash`/`shell`, and the MCP
  shell pattern (`…__bash` / `…__shell`, e.g. `mcp__workspace__bash`), plus an
  explicit `shell_tools` allowlist option. PostToolUse now also walks every string
  leaf of the response, so a leaked value is blocked regardless of the response
  shape (the MCP content shape, not just `{stdout,stderr}`). Verified end-to-end in
  a Linux container driving the real plugin under the exact hook protocol.

## [0.4.0] - 2026-06-15

### Added
- **Transparent per-command secret-rendering sandbox.** The host hook now wraps
  every Bash command as `secrets-guard sandbox -- sh -c '<command>'`. The sandbox
  finds vault references in the **environment** and in **matched files** under the
  working directory (`.env`, `config.yaml`, `settings.json`, `package.json`, …,
  configurable via `sandbox_globs`), resolves them (local vault, or the sealed-box
  channel in the Cowork VM), enters an unprivileged user+mount namespace, renders
  the environment, and **bind-mounts a rendered copy** of each ref-file over the
  original — so apps that read secrets from files just work, not only
  `secrets-guard run --env-file`. The real disk is untouched; rendered values live
  only in an in-memory tmpfs that the kernel discards when the command exits. Any
  command works (pipes, `&&`, redirections, multi-line) — the original is a single
  quoted `sh -c` argument, so the brittle "single simple command" guard is gone.
  Linux only (Cowork VM + Linux Claude Code host); macOS/Windows render the
  environment only. New options: `sandbox` (`auto`/`on`/`off`), `sandbox_globs`.
  Adversarial-reviewed (no Critical/High; renderer hardened against symlink/TOCTOU
  via `O_NOFOLLOW` + `/proc/self/fd` validation and bind-over-inode).

### Changed
- **`cowork_ref_policy` default is now `audit`** (resolve any reference the
  per-command one-time-token-authenticated request asks for, and log each). The
  per-command token is the authorization boundary; `enforce` (only host-observed
  refs) remains as opt-in hardening. This is what lets the sandbox render
  references the host never saw being written.

## [0.3.2] - 2026-06-15

### Fixed
- **Cowork rewrite now allows benign redirections.** The `secrets-guard run` →
  `cw-run` rewrite previously bailed on any `>`/`<`/`&`, so a harmless trailing
  `2>&1` silently fell back to the (correctly refused) local path. It now rewrites
  single simple commands that carry only redirections (`2>&1`, `>`, `<`) — which
  commute with the token's fd-3 here-string — while still rejecting chaining
  (`;`, `&&`, `||`, newline), pipes (`|`), command substitution (`$(`, backtick),
  and backgrounding (`&`).

## [0.3.1] - 2026-06-15

### Removed
- **Removed the legacy TCP broker** (`internal/broker`) and its options
  (`broker_host`, `broker_port`, `execution_mode: broker`). It required host↔VM
  network reachability that does not exist in Cowork; the sealed-box disk channel
  (0.3.0) fully replaces it. `broker_ref_policy` is renamed `cowork_ref_policy`.

## [0.3.0] - 2026-06-15

### Added
- **Claude Cowork support via an asymmetric sealed-box disk channel.** In Cowork the
  agent's commands run in an isolated Linux VM with no vault CLI **and no network to
  the host** — the only host↔VM channel is the shared `outputs` disk. secrets-guard
  resolves references **on the host** (`cw-host` daemon) and delivers each value over
  that disk **sealed** to an ephemeral X25519 key the VM (`cw-run`) generates in RAM
  and never transmits, so a captured request+response is useless. The host signs the
  whole response envelope (Ed25519); the trust anchor (host public key) is delivered
  to the VM via the command **environment** (authoritative over agent argv), and a
  one-time token is delivered on a **file descriptor** (never argv/env/disk), binding
  the request to the VM's key. Reads use `O_NOFOLLOW`; per-exec allowlist (`enforce`)
  bounds what each command can fetch; optional `cowork_isolate` wraps the VM child in
  a namespace. Detection is automatic via `CLAUDE_CODE_IS_COWORK`. New options:
  `execution_mode` (`auto`/`local`/`cowork`), `cowork_spool` (auto-derived from
  `CLAUDE_PROJECT_DIR`), `cowork_isolate`, `cowork_ref_policy`. Plain Claude Code is
  unchanged. See `docs/cowork.md`.
- **Renders three surfaces, escape-aware.** Vault references are rendered in (1)
  files under cwd, (2) environment variables, and (3) the Bash command body itself;
  a leading backslash (`\op://…`) keeps an occurrence literal (the backslash is
  stripped), matching the inline `command_references` escape.

### Security
- **Ten-round adversarial hardening of the sandbox + leak-block.** Fixed: the local
  sandbox wrap now pins `SG_SESSION` so rendered values are recorded for the
  leak-block; the `seen` ledger and the `cache` socket are per-uid + ownership-verified
  + fail-closed (anti hijack/poison/impostor-daemon); the leak-block now covers
  line-wrapped base64 (76/64-col); per-command exec tokens are reaped on a freshness
  window + GC (no lingering replay); the file-render leak-block is pinned across the
  `unshare` uid-map boundary; `tool_output_mode=off` no longer disables the
  resolved-value backstop; the Keeper catalog rejects flag-like ids (ksm
  arg-injection); and `knownInText` corroborates a cache miss against the durable
  ledger (no amnesiac-cache fail-open). No Critical/High remaining.

## [0.2.0] - 2026-06-14

### Added
- **Claude Cowork support via a host↔VM secret broker.** In Cowork the agent's
  commands run in an isolated Linux VM with no vault CLI, while the hooks run on
  the host. secrets-guard now resolves references **on the host** and serves the
  values to the VM over an authenticated, certificate-pinned TLS channel
  (`internal/broker`), where they are used **only in memory** — never on the VM's
  disk, shell history, or the agent transcript. The host `SessionStart` hook starts
  a per-session broker and publishes a control-plane bootstrap (capability token +
  address + cert fingerprint, **never a value**) to the shared `outputs` spool;
  `secrets-guard run`/`read` inside the VM auto-detect broker mode and fetch values
  over the socket. Transport auto-negotiates Plan A (host binds the vmnet bridge,
  VM dials) with a Plan B fallback (VM listens, host dials in). Inline `op://`
  references in Bash are rewritten to `$(secrets-guard read 'op://…')` so the value
  is materialized only at exec time in the VM. New options: `execution_mode`
  (`auto`/`local`/`broker`), `cowork_spool`, `broker_host`, `broker_port`,
  `broker_ref_policy` (`enforce` default / `audit`). Plain Claude Code is
  unchanged. Security model and pentest: `docs/cowork.md`; setup and
  manual test: `docs/cowork.md`.
- **Three capture-the-flag rounds hardened the broker further.** (1) The allowlist
  no longer over-populates from passive text in any tool input (confused deputy).
  (2) In broker mode the value is never made shell-visible — references are kept
  literal and `secrets-guard read` is refused inside the VM, so a heredoc/redirect
  can't write the value to the VM disk; the only value channel is `secrets-guard
  run --env-file` (injects into the child env). (3) Only real `KEY=op://…` lines in
  an env file written through the Write/Edit tool authorize a reference — a bare
  `echo` or prose no longer mints an allowlist entry. See `docs/cowork.md`.
- **Security hardening of the broker (pentest-driven).** Mandatory TLS pinning,
  32-byte minimum capability token, default `enforce` reference allowlist (the host
  authorizes only references it observed this session), per-start token rotation +
  1h TTL with live refresh, request caps (max refs, bounded reads, per-message
  deadlines), refusal to bind all interfaces, single-live-bootstrap discovery
  (fail-closed on ambiguity), and spool cleanup on `SessionEnd`.
- **Automatic, cross-platform CLI install on plugin enable (Linux/macOS/Windows).**
  A new `SessionStart` hook installs the `secrets-guard` CLI into the user's own
  terminal PATH the first time a session starts with the plugin enabled — so just
  installing/enabling the plugin (including when enforced via
  `managed-settings.json`) makes the command available in the developer's shell,
  with **no administrator rights** and no manual step. It is idempotent (re-copies
  only when the bundled binary changes), silent (nothing is added to the model's
  context), and best-effort (never blocks or breaks a session). Destinations:
  `~/.local/bin` on Linux/macOS (added to the shell rc if not already on PATH);
  `%LOCALAPPDATA%\secrets-guard\bin` on Windows (added to the user PATH via
  `HKCU\Environment`, leaving the system PATH untouched). `secrets-guard install`
  is now cross-platform too and remains available as a manual fallback.
- **`command_references` option + per-occurrence control over reference
  injection in commands.** By default a `op://…` / `keeper://…` reference inside a
  Bash command is replaced with its value at execution (`inject`). Now you can keep
  the reference *literal* in the command body instead:
  - Commands that resolve references themselves — `op read`, `op inject`, `op run`,
    `ksm secret notation`, `ksm exec`, `secrets-guard read`, `secrets-guard run` —
    automatically keep the reference literal (injecting the value would break them,
    e.g. `op read "op://…"` was failing with `invalid secret reference
    '[REDACTED BY SECRETS-GUARD]'`).
  - A single occurrence opts out with a leading backslash: `\op://vault/item/field`
    stays literal (the backslash is stripped); other occurrences still resolve.
  - `command_references: keep` keeps every reference literal in every command.

  In all cases the reference is still resolved **internally**, so if the value
  reaches the command's output it is redacted to `[REDACTED BY SECRETS-GUARD]` —
  keeping a reference literal never weakens output redaction.

### Changed
- **Files keep the reference; only commands resolve it.** Write/Edit (and other
  non-Bash tools) no longer inject the secret value — the `op://…` / `keeper://…`
  reference is left in the file, so a plaintext secret never lands on disk, in a
  commit, or in a backup. Bash commands still resolve the value at execution
  (consumed transiently, output redacted). This replaces the previous "inject then
  block the Write result" behavior, which couldn't censor non-Bash output
  (Claude Code does not honor client-side tool-output rewriting).

### Added
- **Skill: migrate hardcoded secrets to the vault.** The bundled skill now
  teaches Claude to detect a hardcoded secret, offer to move it to the vault
  (creating the item with the value piped straight from the file to the CLI —
  never through the chat; the vault prompts for permission), get its reference,
  and refactor. The refactor changes only *how the app starts* (read from env +
  a `start.sh` wrapper using `secrets-guard run`), never the app's behavior, and
  documents the manual run command (op run / ksm exec / secrets-guard run) so the
  developer can launch securely without Claude. Includes startup patterns for
  Node/Python/Go/.NET/Java/Ruby/Make/Procfile/Docker/compose/CI.
- **User-level CLI install + `read`.** `secrets-guard install` (and `./install.sh`)
  copy the binary to `~/.local/bin` so the CLI works in the developer's own shell
  — no administrator privileges. `secrets-guard read REFERENCE…` resolves one or
  more references and prints the values (the op-read / ksm-notation equivalent,
  unified). These make the `start.sh` / manual-run workflow work outside Claude
  Code.
- **`secrets-guard run` (op-run / ksm-exec, unified).** `secrets-guard run
  [--env-file FILE]… -- COMMAND` loads env vars / `.env` files that contain vault
  references, resolves them in memory, and injects the real values as environment
  variables into the child process — **never to disk**. This is how apps
  (Python/Node/Go/.NET) that expect secrets in the environment get their values
  while `.env` keeps only references. Resolved values are registered with the
  session guard so they are redacted if the program prints them.
- **Leak guard for chained tools (taint tracking).** Once a vault reference is
  resolved, the value must never re-enter the conversation (e.g. the model writes
  it to a file and reads it back). secrets-guard now keeps, per Claude session,
  only the references used (paths are not secret — on disk, 0600); the secret
  values are **never stored anywhere**. When a tool result or input arrives, the
  values are cached in a per-session **in-memory daemon** (one process per Claude
  session, behind a 0600 unix socket — never on disk, gone at session end). The
  value is cached once, when first resolved (one vault unlock), and matched
  against later tool I/O from memory, so the vault is not re-read on every tool
  (no repeated Touch ID) and the check does not fail open if the vault later
  locks. If the daemon is unavailable, it falls back to re-resolving the recorded
  references in ephemeral memory. Matching is by direct substring (no hashing —
  exact, O(n·k)). Matches in **any reversible
  encoding** (raw, base64/base64url, base32, hex, URL, JSON, raw bits) are
  blocked (other tools) or redacted with `[REDACTED BY SECRETS-GUARD]` (Bash
  output). The model also cannot pass a resolved value back into a tool. A
  `SessionEnd` hook clears the ledger. All enforcement is in the plugin's hooks —
  no network gateway required.
- **Vault catalog MCP tools + skill.** The plugin now runs an MCP server
  (`secrets-guard mcp`) exposing `vault_status`, `list_accounts`, `list_vaults`,
  `search_secrets`, `list_secrets` and `list_fields`. These return item titles,
  field labels and ready-to-use references (`op://…`, `keeper://…`) but **never
  values**. `search_secrets`/`list_secrets` filter by title and vault and
  paginate (filtering happens in the binary, not by dumping thousands of items to
  the model — large shared vaults no longer blow the token budget); they report
  `total`/`returned`/`truncated`. A bundled skill
  teaches Claude to discover a reference and use it instead of asking for a
  secret. Flow: Claude lists the catalog → gets the reference → puts it in a tool
  → the PreToolUse hook resolves it. The value never enters the conversation.
- **Account-embedded references** for 1Password: `op://<account>:vault/item/field`.
  The account is parsed and passed to `op --account`, so a single session can use
  secrets from several accounts at once. `list_fields` emits this form
  automatically. The account may be an id, sign-in address or email.
- **`op_account` option** to pass `op --account` on machines with multiple
  1Password accounts (config or `OP_ACCOUNT` env).

### Changed
- **Detection is now zero-false-positives by design.** The ruleset only matches
  secrets with a reserved unique prefix (AKIA…, AIza…, ghp_…, sk-ant-…, xox…,
  sk_live_…), an unambiguous block (PEM private keys, JWTs), or a strict
  keyword+format combination (`aws_secret_access_key = <40 base64>`,
  `AccountKey=<88 base64>`). It cannot fire on a filename, identifier, path or
  ordinary sentence. We deliberately accept false negatives over ever blocking a
  developer; the core feature (vault reference resolution) does not depend on
  detection.
- Renamed the repository/marketplace to `hsoft-claude-plugins` (the `secrets-guard`
  plugin lives inside it). Install: `claude plugin install secrets-guard@hsoft-claude-plugins`.
- Dynamic block/deny message names the vault actually installed (Keeper or 1Password).
- 1Password reference parsing handles sections and `?attribute=…`; Keeper handles
  `[predicate]` notation. Findings are guaranteed non-overlapping.

### Removed
- All loose/contextual detectors that could cause false positives:
  natural-language credentials ("the password is X"), generic `key=value`
  secrets, credential URLs (`user:pass@host`), and the entropy/token heuristic.
  Use `custom_patterns_path` to opt into organization-specific patterns.
- The optional llm-guard / Presidio NER layer and its sidecar. The plugin is now
  a single dependency-free Go binary.

### Fixed
- A valid vault reference written to a file (e.g. `op://Private/test-claude/password`
  to `password-ref.txt`) is no longer mistaken for a plaintext secret and blocked.

## [0.1.0] - 2026-06-12

### Added

- `secrets-guard` plugin with three Claude Code hooks:
  - `UserPromptSubmit` blocks prompts containing plaintext secrets.
  - `PreToolUse` resolves `keeper://` / `op://` vault references into tool input
    (the model only ever sees the reference), denies plaintext secrets in tool
    input, and wraps Bash commands so their output is redacted at the source.
  - `PostToolUse` withholds non-Bash tool output that leaks a secret.
- Dependency-free regex/entropy detection layer (AWS, GCP, Azure, JWT, GitHub,
  Slack, Stripe, Anthropic, SSH keys, credential URIs, generic assignments).
- Vault abstraction with Keeper (primary) and 1Password providers, first-found-wins.
- Deterministic, value-stable redaction placeholders.
- Configuration via `CLAUDE_PLUGIN_OPTION_*` (managed-settings.json friendly),
  custom patterns, allowlist, and value-free audit logging.
- Cross-platform binaries and a marketplace for distribution.
