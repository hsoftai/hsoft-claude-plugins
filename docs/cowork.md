# secrets-guard in Claude Cowork (host↔VM broker)

In Claude Code the hooks and the Bash tool run on the same host, so secrets-guard
resolves vault references locally. In **Cowork**, commands run inside an isolated
Linux VM that has **no `op`/`ksm`**, while the hooks run on the **host**.
secrets-guard bridges this with a **broker**: the host resolves references and
serves the values to the VM over an authenticated, pinned TLS channel; the VM uses
them **only in memory** (never on its disk, shell history, or the transcript).

See [security-broker.md](security-broker.md) for the threat model and pentest.

## How it works

1. **SessionStart (host hook):** starts a per-session broker daemon and writes a
   bootstrap (capability token + address + cert fingerprint — **never a value**)
   to the shared `outputs` spool.
2. **Transport (auto):** Plan A — the host binds the vmnet bridge and the VM dials
   in; if that bind is unreachable, Plan B — the VM listens and the host dials in
   (rendezvous via the spool). The value always travels over the TLS socket.
3. **`secrets-guard run --env-file .env -- <cmd>` (in the VM):** the `.env` holds
   only references; the VM client fetches the values from the broker and injects
   them into the child's **environment** (memory). **This is the ONLY value channel
   in the VM** — the value never becomes visible to the shell, so it cannot be
   redirected to disk.
4. **The value never becomes shell-visible.** Inline `op://…` references in a Bash
   command are kept **literal** (not resolved into the shell), and `secrets-guard
   read` is **refused inside the VM** — both would let the shell write the value to
   disk. Put references in a `.env` and consume them via `secrets-guard run`.
5. **Authorization (enforce):** the broker only resolves a reference the host has
   seen as a real `KEY=op://…` line in an env file written through the **Write/Edit
   tool**. Write your `.env` with the Write tool (it keeps the reference); a bare
   `echo`/heredoc does not authorize a reference.
6. **Output:** the host PostToolUse blocks tool output that leaks a resolved value.
7. **SessionEnd (host hook):** removes the broker control-plane files from the spool.

## Configuration

Set these as `CLAUDE_PLUGIN_OPTION_*` in `managed-settings.json` (host side):

| Option | Default | Notes |
|--------|---------|-------|
| `execution_mode` | `auto` | `auto` (local vault if present, else broker), `local`, `broker` |
| `cowork_spool` | – | **Host path** of the shared `outputs` mount (required to enable the broker) |
| `broker_host` | `172.16.10.1` | vmnet bridge IP the host binds/advertises (Plan A) |
| `broker_port` | `8771` | broker TCP port |
| `broker_ref_policy` | `enforce` | `enforce` (deny references the host did not observe) or `audit` (allow + log) |

The VM side needs no configuration: the binary auto-detects broker mode (no local
vault) and discovers the bootstrap in the spool. You can override spool discovery
with `SG_COWORK_SPOOL` if the VM mount path is unusual.

## Manual test in a real Cowork session

The host↔VM transport and the exact spool/port values can only be confirmed on a
real Cowork machine. Run this **inside the Cowork VM** (it talks to the host broker
started by the SessionStart hook). It leaves **no secret on disk**.

```sh
# 0) Confirm the broker bootstrap arrived from the host (control plane only).
find / -name 'broker-*.json' -path '*secrets-guard*' 2>/dev/null | head
#    Inspect it: it must contain token/addr/cert_fp but NO secret value.

# 1) Primary pattern: .env holds the REFERENCE; the child gets the VALUE in env.
printf 'PASSWORD=op://Private/test-claude/password\n' > /tmp/.env
secrets-guard run --env-file /tmp/.env -- sh -c 'echo "len=${#PASSWORD}"'
#    Expect: len=<the real length>, exit 0.

# 2) Anti-leak: the value must NOT be on disk anywhere in the VM.
grep -rIn "$(secrets-guard read 'op://Private/test-claude/password')" /tmp /root "$HOME" 2>/dev/null \
  && echo 'LEAK!' || echo 'OK: value not found on disk'
#    (The command substitution itself holds the value only in this shell's memory.)

# 3) enforce: a reference the host never observed is denied.
secrets-guard read 'op://Private/never-referenced/secret' ; echo "rc=$?"
#    Expect: "broker: ref-not-approved", rc=1  (unless broker_ref_policy=audit).

# 4) Confirm .env still holds only the reference (no value written back).
cat /tmp/.env   # PASSWORD=op://Private/test-claude/password
rm -f /tmp/.env
```

On the **host**, confirm the broker is running and audited without values:

```sh
# the broker daemon for the session
pgrep -fl 'secrets-guard broker'
# audit log (if audit_log_path is set): records show value:<redacted>, never the value
```

### If Plan A is unreachable

If the host cannot bind the vmnet bridge, the bootstrap shows `"plan":"B"` and the
VM listens for the host to dial in (rendezvous via the spool, ~0.5s extra latency).
Both plans are functionally identical to the agent. Record the spool paths and the
working plan from this test and pin them in `managed-settings.json`.
