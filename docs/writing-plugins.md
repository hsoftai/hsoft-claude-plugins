# Adding a plugin to the secrets-guard marketplace

This repository is also a Claude Code **marketplace** (`.claude-plugin/marketplace.json`).
We welcome additional security-focused plugins.

## Layout

```
plugins/
  secrets-guard/                 # the flagship plugin
    .claude-plugin/plugin.json
    hooks/hooks.json             # auto-loaded by convention — do NOT also list it in plugin.json
    bin/                         # prebuilt, committed binaries + launcher
  your-plugin/
    .claude-plugin/plugin.json
    ...
```

## Steps

1. Scaffold `plugins/<your-plugin>/` with a `.claude-plugin/plugin.json`
   (`name`, `version`, `description`, optional `userConfig`).
2. Put hooks in `hooks/hooks.json` (auto-discovered). **Gotcha:** do not also set
   `"hooks"` in `plugin.json` — that double-loads the file and fails with
   "Duplicate hooks file detected".
3. Reference bundled files with `${CLAUDE_PLUGIN_ROOT}` (plugins are copied to a
   cache on install, so relative `../` paths won't resolve).
4. Ship cross-platform binaries via a small launcher (see
   `plugins/secrets-guard/bin/secrets-guard`); `bin/` has no automatic OS
   selection, so detect OS/arch in the launcher.
5. Add an entry to `.claude-plugin/marketplace.json`.
6. Validate:

   ```sh
   claude plugin validate ./plugins/your-plugin
   claude plugin validate .
   ```

## Hook decision contracts that work in Claude Code 2.1.x

Verified empirically (see [architecture.md](architecture.md)):

| Need | Field | Works |
|------|-------|-------|
| Block a prompt | top-level `decision: "block"` (+ `systemMessage`) | yes |
| Deny a tool call | `hookSpecificOutput.permissionDecision: "deny"` | yes |
| Rewrite tool **input** | `hookSpecificOutput.updatedInput` | yes |
| Rewrite tool **output** | `hookSpecificOutput.updatedToolOutput` | **no** (not honored) |
| Withhold tool output | `decision: "block"` in PostToolUse | yes |

Because output rewriting isn't honored, redact Bash output by wrapping the command
in `PreToolUse`, and withhold non-Bash leaks in `PostToolUse`.
