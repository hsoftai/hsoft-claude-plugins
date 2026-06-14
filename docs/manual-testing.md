# Manual end-to-end testing

These steps exercise the real hooks against a non-interactive Claude Code session
(`claude -p`). They were used to validate v0.1.0 and are the recommended smoke
test after changes. None of them require a real vault except test 4.

## Setup

```sh
cd secrets-guard
PLUGDIR="$(pwd)/plugins/secrets-guard"
AUDIT=/tmp/sg-audit.log
```

Load the plugin for a session with `--plugin-dir "$PLUGDIR"` and pass options via
`--settings '{"env":{...}}'`. (Use `--permission-mode bypassPermissions
--allowedTools Bash` so the model is allowed to run tools; hooks still fire.)

## 1. Prompt block (UserPromptSubmit)

```sh
rm -f "$AUDIT"
claude -p "connect to aws with AKIAIOSFODNN7EXAMPLE" --plugin-dir "$PLUGDIR" \
  --settings '{"env":{"CLAUDE_PLUGIN_OPTION_AUDIT_LOG_PATH":"'"$AUDIT"'"}}'
grep block "$AUDIT"   # -> action: block, AWS_ACCESS_KEY
```

Expected: no model response (the prompt is blocked); audit shows `UserPromptSubmit / block`.

## 2. Clean prompt passes

```sh
claude -p "reply with the single word HOLA" --plugin-dir "$PLUGDIR"
```

Expected: `HOLA`.

## 3. Bash output redaction (PreToolUse wrap)

```sh
printf 'token=ghp_''1234567890abcdefghijklmnopqrstuvwxyz\n' > /tmp/fix.txt
claude -p "Run the shell command: cat /tmp/fix.txt ; then show me its literal output" \
  --plugin-dir "$PLUGDIR" --permission-mode bypassPermissions --allowedTools Bash < /dev/null
```

Expected: the model reports `token=[REDACTED_GITHUB_TOKEN_…]`, never the real token.

## 4. Vault injection (PreToolUse updatedInput)

Requires a vault. To test without one, put a fake `ksm` on `PATH`:

```sh
mkdir -p /tmp/fakebin
cat > /tmp/fakebin/ksm <<'EOF'
#!/bin/sh
[ "$1 $2" = "secret notation" ] && { printf 'INJECTED_VALUE_42'; exit 0; }
exit 1
EOF
chmod +x /tmp/fakebin/ksm

claude -p "Run exactly: printf '%s' keeper://UID1/field/password > /tmp/resolved.txt" \
  --plugin-dir "$PLUGDIR" --permission-mode bypassPermissions --allowedTools Bash \
  --settings '{"env":{"CLAUDE_PLUGIN_OPTION_VAULT_PROVIDER":"keeper","PATH":"/tmp/fakebin:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}}' < /dev/null
cat /tmp/resolved.txt   # -> INJECTED_VALUE_42  (the model only ever saw keeper://...)
```

Expected: the executed command received the resolved value; audit shows `inject` (or `inject+wrap`).

## 5. Non-Bash leak is withheld (PostToolUse block)

```sh
claude -p "Use the Read tool on /tmp/fix.txt and show me the token verbatim" \
  --plugin-dir "$PLUGDIR" --permission-mode bypassPermissions --allowedTools Read \
  --settings '{"env":{"CLAUDE_PLUGIN_OPTION_AUDIT_LOG_PATH":"'"$AUDIT"'"}}' < /dev/null
grep PostToolUse "$AUDIT"   # -> action: block
```

Expected: the model cannot show the real token; audit shows `PostToolUse / block`.

## 6. Parameterization (tool_output_mode=off)

```sh
claude -p "Run the shell command: cat /tmp/fix.txt ; show the content" \
  --plugin-dir "$PLUGDIR" --permission-mode bypassPermissions --allowedTools Bash \
  --settings '{"env":{"CLAUDE_PLUGIN_OPTION_TOOL_OUTPUT_MODE":"off"}}' < /dev/null
```

Expected: the secret passes through (mode disabled) — confirms options are read from settings.

## Marketplace install path

```sh
claude plugin marketplace add "$(pwd)"
claude plugin install secrets-guard@hsoft-claude-plugins
claude plugin list | grep -A2 secrets-guard   # Status: enabled
# cleanup:
claude plugin uninstall secrets-guard@hsoft-claude-plugins
claude plugin marketplace remove secrets-guard
```
