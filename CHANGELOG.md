# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  `CLAUDE_PROJECT_DIR`), `cowork_isolate`, `cowork_ref_policy`. Adversarial-reviewed
  (no Critical/High). Plain Claude Code is unchanged. See `docs/cowork.md`.

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
