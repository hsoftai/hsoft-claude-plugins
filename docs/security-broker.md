# Security report — secrets-guard host↔VM broker (Cowork)

Pentest and hardening of the broker that delivers vault-resolved secret values
from the host to the Claude Cowork VM. Scope: `internal/broker/*` and
`cmd/secrets-guard/broker.go`. Method: adversarial code review + an independent
second-pass audit, then targeted unit/E2E tests for each fix.

## Threat model & trust boundary

- The **host** holds the vault CLIs (`op`/`ksm`) and runs the resolving authority
  (broker). The **VM** runs the agent's commands and consumes values **in memory
  only**. The goal: a secret value must never land on the VM's disk, shell
  history, or the agent transcript.
- The **spool** (the shared `outputs` mount) is readable/writable by both host and
  VM; the VM **cannot delete** files there. It carries only the **control plane**
  (capability token, address, cert fingerprint) — **never a secret value**.
- **Explicitly out of scope:** preventing code that already runs *as the agent
  inside the VM* from requesting the secrets the agent itself is authorized to use.
  The VM is the agent's execution environment; anything running there with the
  capability token can request **allowlisted** references — exactly the secrets the
  agent legitimately uses. The broker's job is to keep those values **off the VM's
  durable surfaces** and **scoped to host-approved references**, not to isolate the
  agent from itself.

## Findings and resolution

Severity uses Critical/High/Medium/Low. Status: **Fixed**, **Mitigated**, or
**Accepted** (documented residual risk).

| ID | Severity | Finding | Status | Fix |
|----|----------|---------|--------|-----|
| B-01 | High | Empty `cert_fp` silently disabled TLS pinning (`InsecureSkipVerify`), allowing a TLS-terminating MITM on the bridge. | **Fixed** | Pinning is mandatory: an empty pin is rejected (`pinnedClientTLS`), and the client refuses a Plan A bootstrap / Plan B rendezvous with no `cert_fp`. |
| B-02 | High | Empty/short capability token accepted; `Token()` swallowed decode errors → HMAC with empty key is attacker-computable. | **Fixed** | `minTokenLen = 32` enforced in `serve`, `request`, and `Client.Resolve` before any handshake/dial. Tokens are 32 random bytes. |
| B-04 | High | `audit` policy (was default) resolved **any** requested reference → arbitrary-vault exfiltration. | **Fixed** | Default changed to **`enforce`**: a reference not in the host-observed allowlist is denied (`ref-not-approved`). The host now records refs from **every** tool input (not just Bash) into the allowlist. `audit` remains an explicit, documented opt-in. |
| B-03 | High | Token in spool + 8h TTL + per-session (not per-exec) scope; `exec_id` advertised but never validated. | **Mitigated** | Token **rotates every broker start** (a leftover file's token is dead). Default TTL cut to **1h** with live refresh while the broker runs. `exec_id` is documented as audit-only, not a boundary. Per-exec one-shot tokens noted as future work. |
| B-05 | Medium | Bootstrap discovery fell back to the largest-TTL `broker-*.json`, so a planted/cross-session bootstrap could be selected. | **Fixed** | Discovery prefers an **exact session match**; the fallback accepts a bootstrap **only when exactly one live** bootstrap exists (else fail-closed). |
| B-06 | Medium | Unbounded refs per request, unbounded line read, single connection deadline → DoS / vault-CLI spawn amplification. | **Fixed** | `maxRefsPerRequest = 32` (server rejects `too-many-refs`), `io.LimitReader` caps bytes per connection (`maxConnBytes`), per-message read deadline (`phaseTimeout`), sequential serving. |
| B-07 | Medium | Plan B client bound `0.0.0.0`; host bind had no guard against all-interfaces/public. | **Fixed** | Plan B binds the specific bridge IP; `RunServer` refuses to bind `0.0.0.0`/`::`. |
| B-08 | Medium | Stale bootstrap/rendezvous persisted with a live token (VM cannot delete). | **Fixed** | Token rotation (B-03) kills stale tokens; the broker removes its files on exit, and a `SessionEnd` hook cleans the spool host-side. |
| B-09 | Low | `readMsg` parsed a non-empty errored (truncated) line as a valid message. | **Fixed** | A non-nil read error is always a failure; only fully `\n`-delimited lines are parsed. |
| B-10 | Low | Plan B `resolveViaListen` could briefly leak a goroutine/conn on timeout. | **Mitigated** | Listener closed on timeout unblocks `Accept`; the inner `request` carries its own deadline. Bounded by deadlines. |
| B-11 | Low | Unchecked `*net.TCPAddr` type assertion could panic the daemon. | **Fixed** | Comma-ok assertion; graceful error. |
| B-12 | Info | Verify no value reaches logs/argv/disk. | **Verified** | The value travels only over the TLS socket. Audit logs `Count`, never the value. Resolver errors are returned as a generic `resolve-failed` (no error-text echo). The inline rewrite places the **reference** (`$(secrets-guard read 'op://…')`), never the value, into the command/argv; the value is materialized only at exec time in VM memory. |

### Well-designed (confirmed by the audit)

- HMAC compare is constant-time (`hmac.Equal`); nonces are 256-bit CSPRNG and
  fresh per connection, so captured auth messages cannot be replayed.
- Mutual authentication: the client verifies the server's `auth_ok` MAC before
  sending references, so a rogue server cannot harvest reference names.
- The ephemeral TLS key never leaves memory; the value is never written to the
  spool — the central design goal holds.

## Residual risks (accepted, documented)

1. **In-VM access to approved secrets** — by design (see threat model). A process
   running as the agent in the VM can request allowlisted references. Reduce blast
   radius with `enforce` (default) + short TTL; this is inherent to a shared
   execution environment.
2. **`audit` policy** resolves non-allowlisted references (opt-in). Use only where
   the host cannot reliably observe references; prefer `enforce`.
3. **Rogue bootstrap (integrity, not exfiltration)** — a malicious VM process can
   plant a bootstrap to intercept the legitimate client's *reference names* and
   return *fake* values (a DoS/integrity issue), but **cannot exfiltrate real
   secrets** (it lacks the vault). Mandatory pinning + single-live-bootstrap
   discovery + token rotation limit this; full bootstrap authenticity would need a
   host→VM channel that does not exist in Cowork today.
4. **Inline `$(secrets-guard read 'ref')`** exposes the value in the child's argv
   transiently (VM-local, same trust domain). Prefer the `secrets-guard run
   --env-file` pattern (value only in the child's environ).

## Capture-the-flag rounds (adversarial, flag = a real secret value)

Three further red-team rounds, each finding the single most critical remaining
bug and fixing it before the next round.

| Round | Flag captured | Fix |
|-------|---------------|-----|
| CTF-1 | **Confused-deputy allowlist over-population.** The host recorded into the allowlist every reference appearing as text in ANY tool input (e.g. a `Write` to `NOTES.md`), so the VM could later fetch any secret ever *mentioned*. | Record only references the agent actually uses: executed-Bash commands and env-file writes — not arbitrary passive text. |
| CTF-2 | **Value written to the VM disk via the inline rewrite.** `op://…` inside a heredoc/redirect (`cat > .env <<EOF … op://… EOF`) was rewritten to `$(secrets-guard read …)`, which the shell expanded and wrote the **value** to disk. `secrets-guard read … > file` leaked directly too. | In broker mode the value is NEVER made shell-visible: references are kept **literal** (no `$(secrets-guard read)` rewrite) and `secrets-guard read` is **refused inside the VM**. The only value channel is `secrets-guard run --env-file`, which injects into the child's environment (memory), never the shell or a file. |
| CTF-3 | **Self-minted allowlist.** The allowlist was still populated from any reference *mentioned* in an executed Bash command (`echo op://victim`) or as prose inside a `*.env` file — the VM authored its own authorizations and then pulled the value to disk via `run -- sh -c '… > file'`. | Authorize **only** references that appear as a real `KEY=op://…` value in an env/dotenv file written through the **Write/Edit** tool (parsed like dotenv). Bare Bash commands and prose no longer authorize anything. |

### Rounds 4–13 (ten further adversarial passes)

Ten more red-team rounds. Severity dropped steadily — the last rounds found no
High/Critical, confirming the surface is hardened.

| Round | Finding (severity) | Fix |
|-------|--------------------|-----|
| 4 | **Symlink-following spool write (High)** — the VM pre-plants `broker-<tag>.json.tmp` as a symlink; the host's `os.WriteFile` follows it and overwrites an arbitrary host file. | Spool writes use `O_CREATE\|O_EXCL\|O_WRONLY\|O_NOFOLLOW` (after removing any planted node) and refuse a symlinked spool subdir. |
| 4b | **≤5-char secret evades redaction (Medium)** — `minLen=6` skipped short secrets. | Lowered to `minLen=4` (1–3 byte values skipped to avoid noise). |
| 5 | **Transform-evasion leak (High)** — `… \| rev` / case-fold of a value evaded `knownInText`, reaching the transcript. | `seen.variants` now also covers reverse + case-fold; arbitrary transforms (gzip/ROT-n) are out of scope (network egress gateway). |
| 5b | **Plan B SSRF (Medium)** — the host dialed a VM-controlled rendezvous `Addr`. | Restrict the Plan B dial to the vmnet bridge /24; fail closed if no bridge IP. |
| 6 | (no High/Critical) env-file authorization consistency | `isEnvFileWrite` restricted to Write/Edit (tools whose content is actually parsed). |
| 7 | (no High/Critical) `op --account` flag-smuggling hardening | Reject a `-`-prefixed account and terminate options with `--` before the positional reference. |
| 8 | **`SG_SESSION`-mutation wrap bypass (High, local mode)** — a Bash command could `unset SG_SESSION` to disable `redact-stream`, leaking the raw value to the transcript. | Pin `SG_SESSION` on each `redact-stream` command line (immune to the command's env), and make PostToolUse ALWAYS run the known-value backstop (no longer trusts the wrap). |
| 9 | (no High/Critical) numeric-leaf coverage | `collectStrings` now emits number/bool leaves and object keys, so a numeric secret in tool input is seen by the deny/detect checks. |
| 10 | **Cache-socket impostor (Medium)** — the socket lived in bare `/tmp` with a session-derivable name; a local process could pre-bind and answer `scan` "clean", disabling the backstop. | Moved the socket into a private per-uid `0700` directory. |
| 11 | (no High/Critical) catalog/resolver hardening parity | Applied the `-`-reject + `--` terminator to the catalog `op` invocations too. |
| 12 | **False positive** — claimed the broker-mode backstop was inert; **verified** the host PostToolUse blocks the value (the broker's host-side `OnResolve` populates the host cache/seen). Added a real-ledger regression test. | none (verification + test). |
| 13 | (no High/Critical/Medium — **surface clean**) detector/resolver scheme mismatch (Low) | Aligned `detect.vaultRefPattern` to the resolvable schemes so an unresolvable `vault://…` blob can't mask a plaintext-secret finding. |

**Residual (accepted, inherent):** `secrets-guard run -- <cmd>` injects the value
into the child's environment; a child the agent chooses (`sh -c '… > file'`) can
persist its own environment — identical to `op run` / `ksm exec` semantics. The
allowlist still bounds what a *rogue/non-agent* process in the VM can pull to the
references the workflow declared in its env files, the value never reaches the
spool or the transcript, the default path never persists, and every resolve is
audited. Preventing a fully-controlled agent from misusing a secret it legitimately
needs is out of scope for the broker (it is the agent's own execution environment).

## Verification

- Unit tests (`go test ./internal/broker -race`): Plan A & B end-to-end, auth
  failure, mandatory-pin refusal, short-token rejection, `too-many-refs`,
  all-interfaces bind refusal, ambiguous-discovery fail-closed, no-secret-in-spool.
- E2E (host↔VM simulated on loopback with a fake `op`): `enforce` denies an
  unobserved reference (`ref-not-approved`), `enforce` allows a host-observed
  reference, `audit` allows with logging, the value never appears in any spool
  file, and `SessionEnd` removes the bootstrap.
