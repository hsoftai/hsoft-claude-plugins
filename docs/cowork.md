# secrets-guard in Claude Cowork (sealed-box disk channel)

In Claude Code the hooks and the Bash tool run on the same host, so secrets-guard
resolves vault references locally. In **Cowork**, commands run inside an isolated
Linux VM that has **no `op`/`ksm`** and **no network path to the host** — the only
host↔VM channel is the shared `outputs` disk mount. secrets-guard delivers secrets
over that disk **safely**, using an asymmetric **sealed box** so a value never
touches the VM's disk, shell, argv, env, or the model/transcript. It needs **no
network** — everything flows through the shared `outputs` directory.

## Detection (one plugin, both products)

The host hook detects Cowork deterministically via **`CLAUDE_CODE_IS_COWORK=1`**
(verified empirically; `CLAUDE_CODE_ENTRYPOINT` is `local-agent`, not `cowork`, so
it is not used). Plain Claude Code → local behavior, unchanged. `execution_mode`
(`auto`|`local`|`cowork`) can force the mode.

## How it works

1. **SessionStart (host hook):** spawns a per-session host daemon (`cw-host`). The
   daemon owns a per-session **Ed25519 identity** stored in a HOST-ONLY directory
   (never the shared spool). The host spool path is `CLAUDE_PROJECT_DIR`.
2. **The agent writes `.env`** with vault **references** (`KEY=op://…`). The hook
   records those references into the session allowlist (only real `KEY=ref` lines
   in a `*.env` written via Write/Edit count — least privilege).
3. **`secrets-guard run --env-file .env -- <cmd>` (in the VM):** the host hook
   rewrites this canonical invocation to `cw-run`, injecting, **per command**:
   - the host **public key** and an **exec id** in the command's environment (the
     non-secret trust anchor — authoritative over any agent-supplied argv);
   - a **one-time token** on **file descriptor 3** (a here-string), never argv/env.
4. **`cw-run` (VM):** generates an **ephemeral X25519 keypair in RAM**, proves it
   holds the token with `HMAC(token, exec_id‖its_public_key)`, and writes a request
   (public key + references + MAC) to the spool. It polls for the host's response.
5. **`cw-host` (host):** authenticates the request (token + bound public key),
   checks each reference against the per-exec allowlist (`enforce`), resolves with
   the local vault, **seals** the values to the VM's public key (ECIES:
   X25519→HKDF-SHA256→AES-256-GCM, AAD=exec_id), **signs the whole envelope**
   (Ed25519), writes the response, and retires the one-time token.
6. **`cw-run`** verifies the envelope signature against the command-line anchor,
   opens the sealed blob with its in-memory private key, injects the values into the
   **child process's environment**, and execs the command. The values exist only in
   that process's memory.

Only **public keys and ciphertext** ever touch the disk. The decryption key (the
VM's ephemeral private key) is never transmitted, so capturing the request and the
response off the spool is useless — there is no symmetric key to steal.

## Security properties (adversarial-reviewed)

| Property | Mechanism |
|---|---|
| Confidentiality of the value | Sealed box; private key born/dies in `cw-run` RAM, never transmitted |
| `cw-run` memory | VM's `ptrace_scope=1` blocks cross-process scraping |
| Request auth (H1) | `HMAC(one-time token, exec_id‖recipient_pub)`; token via fd, single-use, binds the VM's key |
| Trust anchor (C1) | Host Ed25519 **public** key via the command **env** (not the spool); agent argv cannot override it |
| Response authenticity (H2) | Signature over the **whole** envelope (`exec_id‖status‖sealed‖error`) |
| Spool reads (M1) | `O_NOFOLLOW` + regular-file check (no symlink/TOCTOU write-through) |
| Anti-DoS (M2) | Caps on refs/request and served execs; idle timer reset **only** on genuine delivery |
| Forgery resilience (M3) | A planted/forged response is ignored; `Fetch` keeps polling for the genuine one |
| Containment | `cowork_ref_policy=enforce` (default) + value-free audit |
| Optional isolation | `cowork_isolate=true` → `unshare --user --map-root-user --pid --mount --fork --mount-proc` |

The irreducible residual is that anything running in the VM *is* the agent: a
co-resident process at the same uid that wins the single-use race could receive a
value it is authorized for. Isolation, the enforce allowlist, single-use tokens,
and value-free auditing raise that cost from "trivial" to "same namespace + win a
single-use race under audit", but cannot make `cw-run` cryptographically distinct
from a co-resident of the same uid.

## Configuration

All optional — Cowork works with defaults:

| Option | Default | Meaning |
|---|---|---|
| `execution_mode` | `auto` | `auto`/`local`/`cowork` |
| `cowork_spool` | (auto) | Host spool path; auto-derived from `CLAUDE_PROJECT_DIR` |
| `cowork_isolate` | `false` | Also add a pid/mount-proc namespace to the sandbox |
| `cowork_ref_policy` | `audit` | `audit` resolves any token-authorized ref + logs; `enforce` only host-observed refs |
| `sandbox` | `auto` | `auto`/`on`/`off` — the transparent env+file rendering sandbox |
| `sandbox_globs` | (defaults) | comma-separated globs the sandbox scans for references |

## The rendering sandbox (default)

The host hook wraps **every** Bash command as `secrets-guard sandbox -- sh -c '<your
command>'`. The sandbox runs in the VM: it finds vault references in the
**environment** and in **matched files** under the working directory (`.env`,
`config.yaml`, `settings.json`, `package.json`, …), fetches the values over the
sealed-box channel, enters a private mount namespace, and renders them — env vars
become their values, and each ref-file is **bind-mounted with a rendered copy** so
the app reads the real secret. The real files keep only references; the rendered
copies live in an in-memory tmpfs that the kernel discards when the command exits.

So secrets "just work" for any loader — dotenv libraries, `source .env`, config
files read directly, framework config — not only `secrets-guard run --env-file`.
Any command works (pipes, `&&`, redirections, multi-line); the original is passed
as a single quoted `sh -c` argument, and the value never appears in the command
text, argv, env of other processes, or the transcript.

```sh
# config.yaml / .env hold REFERENCES (write them with the Write tool):
#   DB_PASSWORD=op://Private/db/password
node app.js          # app.js reads .env → sees the real password (rendered in a private ns)
cat config.yaml      # shows the value (rendered) → the host PostToolUse blocks that output
```

`secrets-guard run --env-file .env -- ./app` still works too (it runs inside the
sandbox, which renders the `.env` first). `secrets-guard read` remains refused in
the VM (it would print a value to a shell that could redirect it to disk).

## Manual test in a real Cowork session

Run **inside the Cowork VM**. It leaves no secret on disk.

```sh
# 1) File rendering: write config with a REFERENCE, read it back through an app.
printf 'PASSWORD=op://Private/test-claude/password\n' > .env   # use the Write tool
node -e 'console.log("len="+require("fs").readFileSync(".env","utf8").split("=")[1].trim().length)'
#    Expect: len=<real password length> (the file read as rendered) — value never printed.

# 2) Anti-leak: after the command, the real file holds only the reference and no
#    value is anywhere on the VM disk.
cat .env                                            # → PASSWORD=op://Private/test-claude/password
grep -rIn "the-known-value" /tmp "$HOME" 2>/dev/null && echo 'LEAK!' || echo 'OK'
```

On the **host**, confirm the daemon and value-free audit:

```sh
pgrep -fl 'secrets-guard cw-host'
# audit log (if audit_log_path set): records show Event=Cowork Action=resolve, never a value.
```
