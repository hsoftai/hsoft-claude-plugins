---
name: using-vault-secrets
description: How to use Keeper / 1Password secrets safely via secrets-guard, and how to migrate hardcoded secrets into the vault. Use whenever the user asks you to connect to something, use a password/API key/token/credential, or fill a secret into a file, command, or config; whenever the user asks what secrets/keys they have or to list/search/create a secret (use the MCP tools — list_secrets, search_secrets, list_fields, create_secret); whenever you find a secret hardcoded in source/config/.env/Dockerfile/CI (offer to move it to the vault and refactor to a reference); and when launching an app that needs secrets (just run it normally — the Bash hook renders the references for that command). Never ask the user to paste a secret value, never call the vault CLI (ksm/keeper/op) yourself, and never write a secret value to disk — discover/keep the reference and let it resolve at runtime.
---

# Using vault secrets without ever seeing their values

secrets-guard lets you use real secrets **without the value ever entering this
conversation**. You work with *references* (`op://…`, `keeper://…`); when a
reference appears in a tool call, the `PreToolUse` hook resolves it to the real
value at execution time. You only ever see the reference.

## Golden rules

1. **Never ask the user to paste a password, key, or token.** If they do, it
   gets blocked/redacted. Instead, find the reference.
2. **Never try to read a secret value** (e.g. `op read`, `ksm secret get --unmask`,
   `cat` a secrets file) just to put the value somewhere. Put the **reference** in
   the tool call and let the hook resolve it.
3. Put references verbatim into the tool that needs the secret (Write content,
   Bash command, config file). Do not modify them.
4. **Never run the vault CLI yourself** (`ksm`, `keeper`, `op`, or `secrets-guard
   read|run`) in a Bash command — the hook denies it. Only the secrets-guard
   service holds the vault credential. To inspect or create secrets, use the **MCP
   tools** (`list_secrets`, `search_secrets`, `list_fields`, `create_secret`,
   `vault_status`); they run the operation through the service and return metadata
   and references only — never a value. To *use* a secret, put its reference in a
   `.env`/config or command and run the command normally (see "Running code").

## Workflow

When the user wants to use a secret ("connect to the prod DB", "use my Stripe
key", "write the DB password into .env"):

1. **Discover** with the MCP tools (they return metadata and references, never
   values):
   - `vault_status` — confirm a vault is active.
   - `list_accounts` — (1Password) see available accounts; use the `id` (the
     uuid, not the url) as `account` in the other tools and references.
   - `list_vaults` — (1Password) see the vaults; use a vault name to narrow.
   - `search_secrets` — **prefer this** to find an item by title. It returns
     `total`/`returned`/`truncated`; if `truncated`, refine `query` or pass a
     `vault`. Use this instead of `list_secrets` for large/shared vaults so you
     don't pull thousands of items.
   - `list_secrets` — list items (capped, paginated; pass `vault` to narrow,
     `limit` to size). Returns `total`/`returned`/`truncated`.
   - `list_fields` — list an item's fields and get the ready-to-use `reference`
     for each. Pass `account` and (if the title isn't unique) `vault`.
   - `create_secret` — create a new record in the vault and get back its
     reference. Pass `title`, the destination (`folder` — a Keeper Shared-Folder
     UID the app can edit, or a 1Password `vault` name), and `fields`
     (label→value, e.g. `{"login":"demo","password":"…"}`). The values are stored
     in the vault through the service; only the new item's metadata + reference
     come back. Use this instead of `op item create` / `ksm secret add` (those are
     blocked, and the client has no credential).
2. **Pick** the field the user means (e.g. the `password` of item `prod-db`).
3. **Use** its `reference`. How depends on the tool — see below.

## Two behaviors you must understand

secrets-guard treats files and commands differently:

- **Files (Write/Edit):** the reference is **left in the file as-is** — the value
  is NEVER written to disk. So writing `DB_PASSWORD=op://7FWKE:Private/prod-db/password`
  to a `.env` leaves exactly that reference in the file. This is correct and safe:
  the secret never lands on disk, in a commit, or in a backup.
- **Bash commands:** the reference IS resolved to the real value at execution,
  and the command's output is redacted so the value never reaches the chat. E.g.
  `PGPASSWORD=op://7FWKE:Private/prod-db/password psql -h db ...` runs with the
  real password; if it prints, it shows `[REDACTED BY SECRETS-GUARD]`.

So **never write a secret value to a file** — write the reference. The value
only ever materializes inside a running command, in memory.

### Keeping a reference literal inside a command

By default, a reference inside a Bash command is replaced by its value at
execution. But sometimes you want the **reference itself** to stay in the command
— typically when you're *writing a script or command that resolves the reference
later* (e.g. `op read "op://…"`, `secrets-guard run`, or generating a `start.sh`).
If the value were injected there, the resulting script would contain the plaintext
secret (bad) or the resolver command would fail (`op read <value>` is invalid).

secrets-guard handles this for you:

- **Resolver commands keep the reference automatically.** `op read`, `op inject`,
  `op run`, `ksm secret notation`, `ksm exec`, `secrets-guard read` and
  `secrets-guard run` are detected; their references are left literal (and still
  resolved internally, so any value in their output is redacted). You can run
  `op read "op://…"` and it works.
- **Escape one occurrence with a backslash.** When you write a command/script
  where a specific `op://…` must stay literal, prefix it with `\`:
  `echo '\op://Private/db/password' >> .env` writes the reference, not the value.
  The backslash is stripped from the output; other occurrences still resolve.
- **Keep them all:** the operator can set `command_references: keep` to make every
  reference in every command stay literal.

Rule of thumb: when the goal is to **use** the secret now (connect, authenticate,
run a query), let it inject. When the goal is to **write down the reference** (a
script, a `.env`, a config the app reads later via `secrets-guard run`), keep it
literal — write the reference, escaping with `\` if needed.

## Claude Cowork (commands run in a VM)

If you are in Cowork, your Bash commands run in an isolated VM that has no vault
CLI. The host resolves references and delivers values to the VM over a secure
sealed-box channel on the shared disk, used **only in process memory**. Two rules
in Cowork:

1. **Consume secrets only via `secrets-guard run --env-file .env -- <cmd>`.** Write
   the `.env` with the **Write tool** (it keeps the reference, e.g.
   `DB=op://Private/db/password`), then run your command through `secrets-guard
   run`. The value is injected into the child's environment and never becomes
   visible to the shell or written to disk.
2. **Inline references and `secrets-guard read` do not return a value in the VM**
   (that would expose the value to the shell, which could write it to disk). So
   `curl -H "Authorization: op://…"` won't work inline — instead put the token in a
   `.env` and run `secrets-guard run --env-file .env -- sh -c 'curl -H
   "Authorization: $TOKEN" …'`.

If a reference fails with `ref-not-approved`, write it as a `KEY=op://…` line in a
`.env` via the Write tool first (that authorizes it), then run. Never paste a value.

## Running code that needs the secrets (the key pattern)

Because `.env` files hold *references*, a normal app (`python-dotenv`, `godotenv`,
node `dotenv`, etc.) would read the literal `op://…` string, not the value. On a
**kernel-DLP / sandbox host (Windows, Linux)** you do nothing special: just run the
app's normal command in Bash and the PreToolUse hook renders every reference — in
the environment **and** in files under the working directory (`.env`, config) —
into real values that only **that command's process subtree** can read. Other
processes, and the files on disk, still see the references. The value never lands
on disk.

```sh
npm run dev            # the .env's keeper://… / op://… is served only to this subtree
node server.js
python app.py
go run .
```

Do **not** wrap these in `secrets-guard run` / `op run` / `ksm exec` yourself — on
a sandbox host the hook already does the rendering, and it denies those resolving
subcommands (only the service may touch the vault). Just run the command as the
project normally would.

Write the app to read config from the **environment** (12-factor):
`os.environ["DB_PASSWORD"]` / `process.env.DB_PASSWORD` / `os.Getenv("DB_PASSWORD")`,
and put the references in `.env`. The value lives only in the process's memory; the
`.env` on disk keeps the reference.

**For the developer running it outside Claude Code** (or on a plain in-place macOS
host), the portable manual command is `secrets-guard run --env-file .env -- <cmd>`
(equivalently `op run --env-file=.env -- <cmd>` for 1Password or `ksm exec -- <cmd>`
for Keeper). That is what goes in the README / `start.sh` for humans — you don't run
it from inside Claude Code on a sandbox host.

## Found a hardcoded secret? Offer to migrate it to the vault

When you see a secret hardcoded in source, config, a `.env` with real values, a
Dockerfile, CI yaml, etc.: **stop and offer to migrate it to the vault.** Do not
silently leave it, and do not just delete it. Say something like: "There's a
hardcoded `<kind>` in `<file>`. I can move it to your vault and refactor the code
to reference it so it never sits in plaintext. Proceed?"

Note: secrets-guard may **withhold the file's content** when you Read it (because
it contains a detected secret), so you might not see the value at all — that's
fine and intended. Locate the secret without revealing it (e.g.
`grep -n 'API_KEY' src/config.py | sed -E 's/(=).*/\1 [hidden]/'` shows the line
and variable but not the value) and handle the value only through shell pipes.

If the user accepts:

1. **Add it to the vault with the `create_secret` MCP tool** (the service writes
   it with its credential; you never call the vault CLI). Pass a `title`, the
   destination (`folder` = a Keeper Shared-Folder UID the app can edit, or a
   1Password `vault` name) and the `fields` (label→value). The tool returns the new
   item's metadata and reference.
   - **Migrating an existing value:** secrets-guard withholds/denies a real
     detected secret in a tool input, so you usually can't paste the existing value
     into `create_secret`. Treat the migration as a **rotation**: create the record
     with a freshly generated value, point the app at the reference, and tell the
     user to update the upstream service with the new value (the old one was in
     plaintext/possibly committed, so it should be rotated anyway). If the value
     must be preserved verbatim, ask the user to add the record in the Keeper /
     1Password app, then continue from `list_fields`.
   - **New secret:** pass the value directly in `fields` (e.g.
     `{"password":"<generated>"}`).
2. **Get the reference** — `create_secret` returns it; otherwise `list_fields`
   returns the ready-to-use, account-prefixed reference.
3. **Refactor** (see rules below).
4. **Verify** the app still starts and behaves the same.
5. Remind the user to **rotate** the secret if it was ever committed to git.

## Refactoring rules — change how it starts, never what it does

The application's behavior must not change. You are only changing **where the
secret comes from** (vault instead of hardcode) and **how the app is launched**.

- **In the code:** replace the hardcoded value with reading from an environment
  variable (12-factor): `os.environ["DB_PASSWORD"]` / `process.env.DB_PASSWORD` /
  `os.Getenv("DB_PASSWORD")` / `Environment.GetEnvironmentVariable("DB_PASSWORD")`
  / `System.getenv("DB_PASSWORD")` / `ENV["DB_PASSWORD"]`. Nothing else in the app
  logic changes. Do **not** add a dependency on secrets-guard inside the app — it
  must stay portable.
- **The `.env`:** put the **reference** there (`DB_PASSWORD=op://Private/myapp-api/credential`).
  References are safe to commit, but to be safe: add `.env` to `.gitignore` and
  commit a `.env.example` with the references (or placeholders).
- **A separate startup wrapper** (the only secrets-guard-specific piece). Leave a
  small script next to the project, e.g. `start.sh`:
  ```sh
  #!/usr/bin/env sh
  exec secrets-guard run --env-file .env -- <THE ORIGINAL RUN COMMAND>
  ```
  Make it executable. The `<ORIGINAL RUN COMMAND>` is exactly how they ran the app
  before (e.g. `python app.py`, `node server.js`, `./app`, `dotnet run`).
- **Make the CLI available in their shell.** This now happens **automatically**:
  the plugin's `SessionStart` hook installs `secrets-guard` into the user's
  terminal PATH the first time a session starts (Linux/macOS `~/.local/bin`,
  Windows `%LOCALAPPDATA%\secrets-guard\bin` + user PATH), user-level and without
  admin. Tell the developer to open a **new terminal** so the PATH refresh takes
  effect. If for some reason it's missing, they can run `secrets-guard install`
  (from inside Claude Code) or `./install.sh` from the repo to (re)install it.
- **Tell the developer how to start it themselves, without Claude Code.** Add a
  short note (in the README or the script header) with the manual command, and
  mention the portable alternatives so they're not locked in:
  ```
  Run securely:   ./start.sh
  Equivalent:     secrets-guard run --env-file .env -- <ORIGINAL RUN COMMAND>
  1Password-only: op run --env-file=.env -- <ORIGINAL RUN COMMAND>
  Keeper-only:    ksm exec -- <ORIGINAL RUN COMMAND>   # with keeper:// in the env
  ```

## Startup patterns by ecosystem (maximize compatibility)

The app reads from env; only the launcher resolves references. These are the
commands the **developer** runs manually / puts in the README or `start.sh` — inside
Claude Code on a sandbox host you just run the bare command (`node server.js`) and
the hook renders the references. Pick what fits:

- **npm/Node:** add a script — `"start:secure": "secrets-guard run --env-file .env -- node server.js"`.
- **Python:** `secrets-guard run --env-file .env -- gunicorn app:app` (or uvicorn,
  `manage.py runserver`, `flask run`). Do **not** also load `.env` with
  python-dotenv — the launcher already populates the env.
- **Go / Rust / compiled:** `secrets-guard run --env-file .env -- ./app`.
- **.NET:** `secrets-guard run --env-file .env -- dotnet run` (or `dotnet App.dll`).
- **Java/JVM:** `secrets-guard run --env-file .env -- java -jar app.jar` (or `./gradlew bootRun`).
- **Ruby/Rails:** `secrets-guard run --env-file .env -- bundle exec rails server`.
- **Make/Task:** a `run-secure` target wrapping the original command.
- **Procfile (Foreman/Honcho):** `web: secrets-guard run --env-file .env -- <cmd>`.
- **Docker:** never bake secrets into the image. Resolve at `docker run` time:
  `secrets-guard run --env-file .env -- docker run -e DB_PASSWORD ... image`.
- **docker compose:** reference `${DB_PASSWORD}` in the compose file and launch
  `secrets-guard run --env-file .env -- docker compose up` so compose inherits the
  resolved env.
- **CI/CD:** don't use the local `.env`; use the platform's secret store or a
  1Password **service account** token. Keep the app's env-var contract identical.

## Migration guardrails

- **Idempotent:** if the secret is already a reference and the code already reads
  from env, don't re-migrate.
- **One `.env` per project;** migrate all hardcoded secrets you find, not just one.
- **Don't break builds:** keep the exact env-var names the app already uses if any.
- **Never echo the value** in any command, log, or message during migration.

## Reference formats

- **1Password:** `op://<vault>/<item>/<field>` and, for multiple accounts,
  `op://<account>:<vault>/<item>/<field>` (the account goes first, separated by
  `:`). The `list_fields` tool already returns the account-prefixed form — use it
  as-is. Sections and attributes are supported:
  `op://<vault>/<item>/<section>/<field>`, `op://<vault>/<item>/<field>?attribute=otp`.
- **Keeper:** `keeper://<record-uid>/field/<label>` (predicates like
  `custom_field/phone[1][number]` are supported).

## If something is missing

- No vault active (`vault_status` says unavailable): tell the user to install/sign
  in to Keeper or 1Password, or set the account. Do not fall back to plaintext.
- A reference fails to resolve (e.g. "multiple accounts"): use `list_accounts`
  and put the right `account` into the reference (`op://<account>:…`).
