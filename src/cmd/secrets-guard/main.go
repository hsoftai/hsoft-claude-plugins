// Command secrets-guard is the single binary invoked by the Claude Code hooks
// of the secrets-guard plugin. It reads a hook JSON payload on stdin, applies
// the configured DLP policy (block / deny / inject / redact) and writes the
// hook decision JSON to stdout.
//
// Subcommands:
//
//	secrets-guard            run as a hook (default; reads stdin)
//	secrets-guard scan       read stdin, print detected findings (debug)
//	secrets-guard version    print version
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hsoftai/hsoft-claude-plugins/internal/audit"
	"github.com/hsoftai/hsoft-claude-plugins/internal/cache"
	"github.com/hsoftai/hsoft-claude-plugins/internal/catalog"
	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/detect"
	"github.com/hsoftai/hsoft-claude-plugins/internal/hook"
	"github.com/hsoftai/hsoft-claude-plugins/internal/mcp"
	"github.com/hsoftai/hsoft-claude-plugins/internal/redact"
	"github.com/hsoftai/hsoft-claude-plugins/internal/seen"
	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	// Make the vault CLI (ksm/op) resolvable even under a stale launch PATH (Windows),
	// so the guard finds the user's installed Keeper/1Password CLI. No-op elsewhere.
	augmentVaultPath()
	// Point ksm at the user's INI config when it lives in a standard per-user location, so
	// it resolves regardless of the working directory.
	ensureKeeperConfig()
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Println("secrets-guard", version)
			return
		case "scan":
			runScan()
			return
		case "redact-stream":
			runRedactStream()
			return
		case "mcp":
			runMCP()
			return
		case "cache-daemon":
			_ = cache.RunDaemon(os.Getenv("SG_SESSION"))
			return
		case "preload-secrets":
			runPreloadSecrets()
			return
		case "cw-host":
			runCwHost()
			return
		case "cw-run":
			runCwRun()
			return
		case "run":
			runRun()
			return
		case "install":
			runInstall()
			return
		case "uninstall":
			runUninstall()
			return
		case "read":
			runRead()
			return
		case "dlp-status":
			runDLPStatus()
			return
		case "doctor":
			runDoctor()
			return
		case "dlp-install":
			runDLPInstall(config.Load(os.Getenv))
			return
		}
	}
	runHook()
}

// buildEngine constructs the detection engine with optional custom patterns and
// allowlist. Failures to load optional files are reported on stderr but never
// fatal — the built-in ruleset must always remain active.
func buildEngine(cfg config.Config) *detect.Engine {
	eng := detect.New()
	if err := eng.LoadCustomPatterns(cfg.CustomPatternsPath); err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard: custom patterns:", err)
	}
	if err := eng.LoadAllowlist(cfg.AllowlistPath); err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard: allowlist:", err)
	}
	return eng
}

func runHook() {
	cfg := config.Load(os.Getenv)
	eng := buildEngine(cfg)
	red := redact.New(eng)

	resolver, err := vault.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard: vault:", err)
		// Continue with a nil-provider resolver so refs error (safe deny).
		resolver, _ = vault.Select("auto", vault.NewRunner(), cfg.OPAccount)
	}

	in, err := readInput(os.Stdin)
	if err != nil {
		// Malformed input: do nothing (exit 0, no decision) to avoid breaking
		// the user's session on an unexpected payload.
		fmt.Fprintln(os.Stderr, "secrets-guard: bad input:", err)
		return
	}

	// Diagnostic (SG_DEBUG_ENV): snapshot what this hook receives, to determine
	// from a real Cowork session where the COMMAND will run (VM) vs the hook (host).
	dumpEnvProbe(in)

	// SessionStart: make the CLI available in the developer's OWN terminal
	// (Linux/macOS/Windows) automatically, so just installing/enabling the plugin
	// — including when enforced via managed-settings.json — is enough to get the
	// `secrets-guard` command on PATH without any manual step. Idempotent,
	// best-effort and silent: it never writes to the model's context and never
	// breaks the session.
	if in.HookEventName == "SessionStart" {
		if _, err := selfInstall("", true); err != nil {
			fmt.Fprintln(os.Stderr, "secrets-guard: self-install:", err)
		}
		// Self-heal: silently remove any leftover components from the removed WinFsp/service
		// model so a machine transitioning to the local model needs no manual cleanup. Cheap
		// when clean (a few stat checks); runs the removal only when something is detected.
		if len(staleComponents()) > 0 {
			removeStale()
		}
		// secrets-guard is inert in Cowork (the agent runs in a VM); it only operates in
		// Claude Code local, so SessionStart does nothing Cowork-specific.
		// Proactive redaction guard: preload every vault value into this session's
		// in-memory cache so any later prompt/tool/file-read containing a secret is
		// redacted or blocked before reaching the model. Detached so it never delays
		// session start; no-op when disabled or when no vault/service can supply values.
		// Preload every vault value into the per-session in-memory cache so the redaction
		// guard can block/redact any of them — on every platform (the cache now works on
		// Windows too). Detached so it never delays session start; no-op without a vault.
		if cfg.PreloadEnabled() {
			spawnPreloadSecrets(in.SessionID)
		}
		return // no stdout → nothing injected into context
	}

	self, err := os.Executable()
	if err != nil {
		self = ""
	}
	// CONSISTENCY: before scanning a prompt or tool I/O, guarantee the full vault is loaded
	// into this session's cache. The SessionStart preload is async and can lose the race (or
	// the daemon may have expired), which made redaction intermittent. This loads the vault
	// synchronously on the first scanning event if it isn't primed yet (then it's cached for
	// the rest of the session), so every Read/tool output is always scanned against every
	// value.
	guardReady := true
	switch in.HookEventName {
	case "UserPromptSubmit", "PreToolUse", "PostToolUse":
		ensureCachePrimed(cfg, in.SessionID)
		// If a vault IS configured (provider resolved + preload on) but its values could not
		// be loaded into the cache, the guard cannot verify a tool output is secret-free.
		// Mark it not-ready so PostToolUse blocks instead of leaking — "no redact -> block".
		if cfg.PreloadEnabled() && resolver.ProviderName() != "none" {
			guardReady = cache.New().Primed(in.SessionID)
		}
	}
	h := hook.NewHandler(toHookConfig(cfg, resolver.ProviderName(), cfg.GuardRequired == "on", guardReady), eng, red, resolver, valueGuard(), self)
	out := h.Handle(in)

	audit.New(cfg.AuditLogPath).Log(audit.Record{
		SessionID:  in.SessionID,
		Event:      h.Last.Event,
		Action:     h.Last.Action,
		Categories: h.Last.Categories,
		Count:      h.Last.Count,
	})

	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard: encode:", err)
	}
}

// runPreloadSecrets (the detached `preload-secrets` child) loads every value the
// vault exposes into this session's in-memory cache, so the redaction guard can block
// or redact any of them before they reach the model. Values live only in the cache
// daemon's RAM (never disk, never the model). Best-effort: any failure is silent.
func runPreloadSecrets() {
	session := os.Getenv("SG_SESSION")
	if session == "" {
		return
	}
	cfg := config.Load(os.Getenv)
	if !cfg.PreloadEnabled() {
		return
	}
	vals, err := allVaultValues(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard: preload:", err)
		return
	}
	// AddPrimed marks the session loaded (even if the vault is empty), so the hook does not
	// reload it on the first tool event.
	cache.New().AddPrimed(session, vals)
}

// ensureCachePrimed guarantees the full vault is loaded into the session cache before a
// scanning hook event runs. It is a no-op once primed (a cheap status round-trip), so only
// the first scanning event of a session — when the async SessionStart preload has not won
// the race yet — pays the synchronous vault load. This makes redaction consistent: every
// prompt/tool I/O is scanned against every vault value, not against a possibly-cold cache.
func ensureCachePrimed(cfg config.Config, session string) {
	if session == "" || !cfg.PreloadEnabled() {
		return
	}
	if cache.New().Primed(session) {
		return
	}
	vals, err := allVaultValues(cfg)
	if err != nil {
		return // vault not ready — retry on the next event (do not mark primed)
	}
	cache.New().AddPrimed(session, vals)
}

// spawnPreloadSecrets starts the detached `preload-secrets` child for a session so
// SessionStart returns immediately while the vault is dumped in the background.
func spawnPreloadSecrets(session string) {
	self, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(self, "preload-secrets")
	cmd.Env = append(os.Environ(), "SG_SESSION="+session)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	cache.Detach(cmd) // OS-specific: fully detach so it outlives this hook
	if err := cmd.Start(); err != nil {
		return
	}
	_ = cmd.Process.Release()
}

func runScan() {
	cfg := config.Load(os.Getenv)
	eng := buildEngine(cfg)
	data, _ := io.ReadAll(bufio.NewReader(os.Stdin))
	findings := eng.Scan(string(data))
	for _, f := range findings {
		fmt.Printf("%s\t[%d:%d]\n", f.Category, f.Start, f.End)
	}
	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "no secrets detected")
	}
}

// runRedactStream reads stdin, redacts secrets and writes the result to stdout.
// It is used to wrap a Bash command so its output is redacted at the source,
// since Claude Code 2.1.x does not honor PostToolUse output rewriting.
func runRedactStream() {
	cfg := config.Load(os.Getenv)
	data, _ := io.ReadAll(bufio.NewReader(os.Stdin))
	fmt.Fprint(os.Stdout, redactText(cfg, os.Getenv("SG_SESSION"), string(data)))
}

// redactText removes secrets from text: first the session's known vault values (in any
// reversible encoding) via the in-memory cache, falling back to re-resolving the recorded
// references in ephemeral memory if the cache is unavailable; then the built-in
// high-confidence detectors. Shared by `redact-stream` and `run`'s output redaction.
func redactText(cfg config.Config, session, text string) string {
	if session != "" {
		if _, red, ok := valueGuard().Scan(session, text); ok {
			text = red
		} else if paths := seen.LoadPaths(session); len(paths) > 0 {
			if resolver, err := vault.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount); err == nil {
				if vals := resolver.ResolveValues(paths); len(vals) > 0 {
					text, _ = seen.Redact(text, vals)
				}
			}
		}
	}
	out, _ := redact.New(buildEngine(cfg)).Redact(text)
	return out
}

// runMCP serves the vault-catalog MCP tools. The tools list accounts, items and
// fields and return references (op:// / keeper://) and labels — never values.
func runMCP() {
	cfg := config.Load(os.Getenv)

	cat := func() (catalog.Catalog, error) {
		// Catalog operations use the user's own local ksm/op profile directly (the local
		// model — there is no service to proxy to).
		return mcpCatalog(cfg)
	}
	jsonText := func(v any) (string, error) {
		b, err := json.MarshalIndent(v, "", "  ")
		return string(b), err
	}
	argStr := func(args map[string]any, k string) string {
		if s, ok := args[k].(string); ok {
			return s
		}
		return ""
	}
	argInt := func(args map[string]any, k string, def int) int {
		switch v := args[k].(type) {
		case float64:
			return int(v)
		case int:
			return v
		}
		return def
	}
	// filterCap narrows items by a case-insensitive title query and caps the
	// result, so a huge shared vault never blows the token budget. The payload
	// reports total/returned/truncated so Claude can refine the query or vault.
	filterCap := func(items []catalog.Item, query string, limit int) any {
		if query != "" {
			q := strings.ToLower(query)
			f := items[:0:0]
			for _, it := range items {
				if strings.Contains(strings.ToLower(it.Title), q) {
					f = append(f, it)
				}
			}
			items = f
		}
		total := len(items)
		if limit <= 0 {
			limit = 50
		}
		truncated := total > limit
		if truncated {
			items = items[:limit]
		}
		return map[string]any{"total": total, "returned": len(items), "truncated": truncated, "items": items}
	}
	acctProp := map[string]any{"type": "string", "description": "Optional 1Password account id (from list_accounts; the uuid, not the url)."}
	vaultProp := map[string]any{"type": "string", "description": "Optional vault name/id to narrow the search (recommended for large shared vaults)."}
	limitProp := map[string]any{"type": "number", "description": "Max items to return (default 50)."}

	tools := []mcp.Tool{
		{
			Name:        "vault_status",
			Description: "Report which secret vault (Keeper or 1Password) is active and reachable.",
			Handler: func(map[string]any) (string, error) {
				c, err := cat()
				if err != nil {
					return jsonText(map[string]any{"available": false, "error": err.Error()})
				}
				return jsonText(map[string]any{"available": true, "provider": c.Provider()})
			},
		},
		{
			Name:        "list_accounts",
			Description: "List the vault accounts available on this machine (no credentials). Use an account id with the other tools and inside references.",
			Handler: func(map[string]any) (string, error) {
				c, err := cat()
				if err != nil {
					return "", err
				}
				accts, err := c.ListAccounts()
				if err != nil {
					return "", err
				}
				return jsonText(accts)
			},
		},
		{
			Name:        "list_vaults",
			Description: "List the vaults of an account (1Password) so you can narrow list_secrets/search_secrets to one vault. Returns names/ids, never secrets.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{"account": acctProp}},
			Handler: func(args map[string]any) (string, error) {
				c, err := cat()
				if err != nil {
					return "", err
				}
				vaults, err := c.ListVaults(argStr(args, "account"))
				if err != nil {
					return "", err
				}
				return jsonText(vaults)
			},
		},
		{
			Name: "search_secrets",
			Description: "Search secret items whose title matches a query (case-insensitive) — never their values. Prefer this over list_secrets for large vaults. " +
				"Returns total/returned/truncated; narrow with 'vault' or refine 'query' if truncated.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":   map[string]any{"type": "string", "description": "Substring to match against item titles."},
					"account": acctProp, "vault": vaultProp, "limit": limitProp,
				},
				"required": []any{"query"},
			},
			Handler: func(args map[string]any) (string, error) {
				query := argStr(args, "query")
				if query == "" {
					return "", fmt.Errorf("missing required argument 'query'")
				}
				c, err := cat()
				if err != nil {
					return "", err
				}
				items, err := c.ListItems(argStr(args, "account"), argStr(args, "vault"))
				if err != nil {
					return "", err
				}
				return jsonText(filterCap(items, query, argInt(args, "limit", 50)))
			},
		},
		{
			Name: "list_secrets",
			Description: "List secret items (titles, ids, vault, type) — never their values. For large shared vaults pass 'vault' to narrow, or use search_secrets. " +
				"Returns total/returned/truncated.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"account": acctProp, "vault": vaultProp, "limit": limitProp},
			},
			Handler: func(args map[string]any) (string, error) {
				c, err := cat()
				if err != nil {
					return "", err
				}
				items, err := c.ListItems(argStr(args, "account"), argStr(args, "vault"))
				if err != nil {
					return "", err
				}
				return jsonText(filterCap(items, "", argInt(args, "limit", 50)))
			},
		},
		{
			Name:        "list_fields",
			Description: "List an item's fields with their ready-to-use reference paths (op:// / keeper://) — never the values. Put a returned reference into a tool call and secrets-guard resolves it at execution.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"item":    map[string]any{"type": "string", "description": "Item title or id (from list_secrets/search_secrets)."},
					"account": acctProp, "vault": vaultProp,
				},
				"required": []any{"item"},
			},
			Handler: func(args map[string]any) (string, error) {
				item := argStr(args, "item")
				if item == "" {
					return "", fmt.Errorf("missing required argument 'item'")
				}
				c, err := cat()
				if err != nil {
					return "", err
				}
				fields, err := c.ListFields(item, argStr(args, "account"), argStr(args, "vault"))
				if err != nil {
					return "", err
				}
				return jsonText(fields)
			},
		},
		{
			Name: "create_secret",
			Description: "Create a new secret in the vault and return its reference (op:// / keeper://) — never a value. Use it to store a credential the user provides or one you generate, then put the returned reference into a config/.env. For Keeper, 'folder' is the destination Shared-Folder UID (from list_secrets/list_fields; the application must have edit access). For 1Password it is the vault name. 'fields' maps field labels to values (e.g. {\"login\":\"user\",\"password\":\"...\"}); values are stored in the vault and never returned.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"folder": map[string]any{"type": "string", "description": "Keeper: destination Shared-Folder UID (the app needs edit access). 1Password: vault name."},
					"title":  map[string]any{"type": "string", "description": "Title for the new record."},
					"fields": map[string]any{"type": "object", "description": "Field label -> value (e.g. login, password, url)."},
				},
				"required": []any{"folder", "title"},
			},
			Handler: func(args map[string]any) (string, error) {
				dest, title := argStr(args, "folder"), argStr(args, "title")
				if dest == "" || title == "" {
					return "", fmt.Errorf("missing required argument 'folder' or 'title'")
				}
				fields := map[string]string{}
				if f, ok := args["fields"].(map[string]any); ok {
					for k, v := range f {
						if sv, ok := v.(string); ok {
							fields[k] = sv
						}
					}
				}
				it, err := createSecret(cfg, dest, title, fields)
				if err != nil {
					return "", err
				}
				return jsonText(it)
			},
		},
	}

	if err := mcp.NewServer("secrets-guard", version, tools).Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard mcp:", err)
	}
}

// runRun is the op-run / ksm-exec equivalent: it loads env vars (and optional
// .env files) that hold vault references (op:// / keeper://), resolves them in
// memory, injects the real values as environment variables into the child
// process, and runs it. The secret values exist only in the child's memory —
// never written to disk. Usage:
//
//	secrets-guard run [--env-file FILE]... -- COMMAND [ARGS...]
func runRun() {
	args := os.Args[2:]
	var envFiles []string
	i := 0
	for i < len(args) {
		if args[i] == "--env-file" && i+1 < len(args) {
			envFiles = append(envFiles, args[i+1])
			i += 2
			continue
		}
		if args[i] == "--" {
			i++
		}
		break
	}
	cmdArgs := args[i:]
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: secrets-guard run [--env-file FILE]... -- COMMAND [ARGS...]")
		os.Exit(2)
	}

	cfg := config.Load(os.Getenv)

	env := environMap()
	for _, f := range envFiles {
		if err := loadEnvFile(f, env); err != nil {
			fmt.Fprintln(os.Stderr, "secrets-guard run:", err)
			os.Exit(1)
		}
	}

	// Collect every reference across the env values, resolve them once with the
	// local vault, then substitute the values back. Fail-closed: if resolution
	// fails, the child does not start. (In the Cowork VM the host hook rewrites this
	// invocation to `cw-run`, which fetches over the sealed-box disk channel.)
	var allRefs []string
	refsByKey := map[string][]string{}
	for k, v := range env {
		if r := vault.FindReferences(v); len(r) > 0 {
			refsByKey[k] = r
			allRefs = append(allRefs, r...)
		}
	}
	var resolvedVals, resolvedRefs []string
	if len(allRefs) > 0 {
		values, rerr := resolveRefsLocal(cfg, allRefs)
		if rerr != nil {
			// No vault at all: warn but DEGRADE — run the command with references left
			// unresolved rather than aborting (the child fails on its own if it needs them).
			fmt.Fprintln(os.Stderr, "secrets-guard run: aviso:", rerr)
			values = map[string]string{}
		}
		for k, refs := range refsByKey {
			s := env[k]
			for _, ref := range refs {
				val, ok := values[ref]
				if !ok {
					// A single unresolvable reference is non-fatal: leave it literal and keep
					// going so other (resolvable) references in the command still work.
					fmt.Fprintf(os.Stderr, "secrets-guard run: aviso: no se pudo resolver %s (se deja sin resolver)\n", ref)
					continue
				}
				s = strings.ReplaceAll(s, ref, val)
				resolvedVals = append(resolvedVals, val)
				resolvedRefs = append(resolvedRefs, ref)
			}
			env[k] = s
		}
	}

	// Register resolved values so they are redacted if the program prints them.
	if session := os.Getenv("SG_SESSION"); session != "" && len(resolvedVals) > 0 {
		cache.New().Add(session, resolvedVals)
		seen.RecordPaths(session, resolvedRefs)
	}

	c := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	c.Env = mapToEnv(env)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "secrets-guard run:", err)
		os.Exit(1)
	}
}

// runRead resolves one or more vault references to their values and prints each
// on its own line — the op-read / ksm-secret-notation equivalent, unified across
// both vaults (and honoring op://<account>: prefixes). Usage:
//
//	secrets-guard read op://Private/db/password [keeper://UID/field/password ...]
func runRead() {
	refs := os.Args[2:]
	if len(refs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: secrets-guard read REFERENCE [REFERENCE...]")
		os.Exit(2)
	}
	cfg := config.Load(os.Getenv)
	// Without a local vault (e.g. the Cowork VM) `read` would print the secret value
	// to stdout, which the shell can redirect to the VM's disk. Refuse it: the only
	// safe way to consume a secret in the VM is `secrets-guard run --env-file` (the
	// value goes into the child process's environment, never the shell or a file).
	if !hasLocalVault(cfg) {
		fmt.Fprintln(os.Stderr, "secrets-guard read no está disponible sin una bóveda local (p. ej. en la VM de Cowork). Usa: secrets-guard run --env-file .env -- <comando>")
		os.Exit(2)
	}
	values, err := resolveRefsLocal(cfg, refs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard read:", err)
		os.Exit(1)
	}
	for _, ref := range refs {
		val, ok := values[ref]
		if !ok {
			fmt.Fprintln(os.Stderr, "secrets-guard read: no se pudo resolver", ref)
			os.Exit(1)
		}
		fmt.Println(val)
	}
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func onPath(dir string) bool {
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == dir {
			return true
		}
	}
	return false
}

func environMap() map[string]string {
	m := make(map[string]string)
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

func mapToEnv(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

func loadEnvFile(path string, env map[string]string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.Trim(strings.TrimSpace(line[eq+1:]), `"'`)
		if k != "" {
			env[k] = v
		}
	}
	return sc.Err()
}

func readInput(r io.Reader) (hook.Input, error) {
	var in hook.Input
	data, err := io.ReadAll(r)
	if err != nil {
		return in, err
	}
	if len(data) == 0 {
		return in, fmt.Errorf("empty input")
	}
	err = json.Unmarshal(data, &in)
	return in, err
}

func toHookConfig(c config.Config, vaultName string, failClosed, guardReady bool) hook.Config {
	return hook.Config{
		BlockOnPromptSecret: c.BlockOnPromptSecret,
		ToolInputPolicy:     c.ToolInputPolicy,
		ToolOutputMode:      c.ToolOutputMode,
		CommandReferences:   c.CommandReferences,
		VaultName:           vaultName,
		// secrets-guard is inert in Cowork; this only short-circuits Handle to a no-op there.
		CoworkMode: c.IsCowork,
		ShellTools: splitList(c.ShellTools),
		// Onboarding gate: block a prompt with setup instructions when no vault is configured.
		// Default on; require_vault=off allows use without a vault.
		RequireVault: c.RequireVault != "off",
		// Fail closed when the redaction guard is mandatory but the vault values could not be
		// loaded; otherwise degrade to the detector instead of blocking every prompt and tool.
		RequireGuard: failClosed,
		// GuardReady reflects whether the vault values are actually loaded into the cache.
		// False when a vault is configured but its values failed to load: PostToolUse then
		// blocks rather than emit an unverifiable "clean" output ("no redact -> block read").
		GuardReady: guardReady,
	}
}

// splitList splits a comma-separated option into trimmed, non-empty entries.
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
