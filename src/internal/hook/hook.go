// Package hook implements the Claude Code hook contracts for secrets-guard.
// A single Handler dispatches on hook_event_name and produces the exact JSON
// decision each event expects:
//
//   - UserPromptSubmit: block a prompt that contains a plaintext secret.
//   - PreToolUse:       resolve vault references into the tool input
//     (updatedInput) so the model never sees the value, or deny a tool call
//     that carries a plaintext secret.
//   - PostToolUse:      redact secrets leaked in the tool result
//     (updatedToolOutput), or block it.
package hook

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hsoftai/hsoft-claude-plugins/internal/detect"
	"github.com/hsoftai/hsoft-claude-plugins/internal/redact"
	"github.com/hsoftai/hsoft-claude-plugins/internal/seen"
)

// Input is the JSON payload Claude Code delivers on stdin.
type Input struct {
	HookEventName  string          `json:"hook_event_name"`
	SessionID      string          `json:"session_id"`
	Cwd            string          `json:"cwd"`
	TranscriptPath string          `json:"transcript_path"`
	Prompt         string          `json:"prompt"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
}

// HookSpecificOutput carries the per-event decision fields.
type HookSpecificOutput struct {
	HookEventName            string          `json:"hookEventName"`
	PermissionDecision       string          `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string          `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             json.RawMessage `json:"updatedInput,omitempty"`
	UpdatedToolOutput        string          `json:"updatedToolOutput,omitempty"`
	AdditionalContext        string          `json:"additionalContext,omitempty"`
}

// Output is the JSON decision written to stdout.
type Output struct {
	Decision           string              `json:"decision,omitempty"`
	Reason             string              `json:"reason,omitempty"`
	SystemMessage      string              `json:"systemMessage,omitempty"`
	SuppressOutput     bool                `json:"suppressOutput,omitempty"`
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

// Resolver resolves vault references (keeper://, op://, ...) inside a string,
// returning the rewritten string and the resolved values. It can also re-resolve
// a list of references to their values (to re-derive a session's secrets in
// ephemeral memory) and find references in text.
type Resolver interface {
	ResolveString(s string) (string, []string, error)
	ResolveValues(refs []string) []string
	FindRefs(s string) []string
}

// SecretCache is the per-session in-memory value cache: resolved values are
// added once and matched against later tool I/O without re-resolving the vault.
// Scan's ok is false when the cache is unavailable (caller falls back).
type SecretCache interface {
	Add(session string, values []string)
	Scan(session, text string) (found bool, redacted string, ok bool)
	Shutdown(session string)
}

// Config holds the runtime policy, populated from CLAUDE_PLUGIN_OPTION_* env.
type Config struct {
	BlockOnPromptSecret bool
	ToolInputPolicy     string // deny | redact | warn
	ToolOutputMode      string // redact | block | off
	CommandReferences   string // inject | keep
	VaultName           string // active vault: "keeper" | "1password" | "none"
	// CoworkMode is true on a Cowork host: the agent's tools run in a VM, so the
	// value is never injected into the command (it would leak to the VM / the host
	// transcript). References are kept literal, and the canonical
	// `secrets-guard run --env-file` invocation is rewritten to `cw-run` with the
	// per-command trust anchor (host public key) + one-time token (via fd), which
	// fetches the value over the sealed-box disk channel.
	CoworkMode bool
	// CoworkIsolate wraps the VM child in a user/pid/mount namespace (unshare).
	CoworkIsolate bool
	// SandboxMode wraps every Bash command in `secrets-guard sandbox`, which renders
	// references (env + files under cwd) into real values inside an ephemeral
	// per-command mount namespace. On a Cowork host this also carries the anchor +
	// one-time token (CoworkMode). True on Cowork and on a Linux Claude Code host.
	SandboxMode bool
	// ShellTools are extra tool names (beyond "Bash" and the built-in MCP shell
	// pattern) to treat as command-execution tools, from the shell_tools option.
	ShellTools []string
}

// CoworkAnchor mints, per command, the trust anchor for a fetch that will run in
// the Cowork VM: an exec id, the host Ed25519 public key (base64, delivered on the
// command line) and a one-time token (delivered to the VM over a file descriptor).
// The implementation persists {exec id -> token, allowed refs} in a HOST-ONLY
// directory the daemon reads. ok=false when Cowork host state is unavailable.
type CoworkAnchor interface {
	Mint(session string, allowedRefs []string) (execID, hostPubB64, tokenB64 string, ok bool)
}

// Decision is a structured audit record produced by Handle (no secret values).
type Decision struct {
	Event      string
	Action     string // block | deny | inject | redact | allow
	Categories []string
	Count      int
}

// Handler bundles policy and detection/redaction/vault dependencies.
type Handler struct {
	cfg      Config
	eng      *detect.Engine
	red      *redact.Redactor
	vault    Resolver
	cache    SecretCache
	selfPath string       // absolute path to this binary, used for Bash output wrapping
	anchor   CoworkAnchor // mints the per-command Cowork trust anchor (nil outside Cowork)

	// Last holds the audit record of the most recent Handle call.
	Last Decision
}

// SetCoworkAnchor installs the Cowork anchor minter (host side). Without it, the
// Cowork command rewrite falls back to keeping references literal.
func (h *Handler) SetCoworkAnchor(a CoworkAnchor) { h.anchor = a }

// NewHandler builds a Handler. selfPath is the absolute path to the
// secrets-guard binary; it is used to wrap Bash commands so their output is
// redacted at the source (Claude Code does not honor PostToolUse output
// rewriting).
func NewHandler(cfg Config, eng *detect.Engine, red *redact.Redactor, vault Resolver, cache SecretCache, selfPath string) *Handler {
	return &Handler{cfg: cfg, eng: eng, red: red, vault: vault, cache: cache, selfPath: selfPath}
}

// knownInText reports whether text contains a secret value resolved earlier this
// session. It uses the in-memory cache when available, and falls back to
// re-resolving the recorded references (ephemeral) when the cache is down.
//
// SECURITY (amnesiac-cache fail-open): the cache daemon holds values in RAM only
// and forgets them on restart (idle timeout, crash, or a fresh daemon replacing an
// exited one that held earlier values). A live-but-amnesiac daemon answers a `scan`
// with found=false, ok=true for a value that IS still in the durable on-disk `seen`
// ledger — so trusting a cache "not found" would silently let a previously-resolved
// value round-trip to the model, defeating the core invariant. The asymmetry is the
// fix: a cache HIT is always authoritative (a positive can never be an amnesiac false
// negative), but a cache MISS must be corroborated against the durable ledger before
// we conclude "clean". The ledger fallback re-resolves references in ephemeral memory
// (no disk values) and is only paid when the cache missed — the common case (truly
// clean text) is a single inexpensive re-resolve, and a real hit short-circuits it.
func (h *Handler) knownInText(session, text string) bool {
	if found, _, ok := h.cache.Scan(session, text); ok && found {
		return true // cache hit is authoritative; never an amnesiac false negative
	}
	// Cache unavailable OR cache reported "not found": corroborate against the
	// durable reference ledger so an amnesiac (restarted) daemon cannot fail open.
	return seen.Contains(text, h.sessionValues(session))
}

// Handle routes an Input to the matching event handler.
func (h *Handler) Handle(in Input) Output {
	switch in.HookEventName {
	case "UserPromptSubmit":
		return h.handlePrompt(in)
	case "PreToolUse":
		return h.handlePreTool(in)
	case "PostToolUse":
		return h.handlePostTool(in)
	case "SessionEnd":
		h.cache.Shutdown(in.SessionID)
		seen.Clear(in.SessionID)
		h.Last = Decision{Event: "SessionEnd", Action: "allow"}
		return Output{}
	default:
		h.Last = Decision{Event: in.HookEventName, Action: "allow"}
		return Output{}
	}
}

// sessionValues re-derives, in ephemeral memory, the secret values of every
// reference used so far this session (never stored as plaintext). Returns nil if
// nothing has been resolved yet.
func (h *Handler) sessionValues(session string) []string {
	paths := seen.LoadPaths(session)
	if len(paths) == 0 {
		return nil
	}
	return h.vault.ResolveValues(paths)
}

func (h *Handler) handlePrompt(in Input) Output {
	// Core invariant (always on, independent of BlockOnPromptSecret): a prompt must
	// never carry a real vault secret value into the model's context. With the
	// proactive guard, every vault value is preloaded into the session cache, so this
	// blocks a pasted secret even when it matches no heuristic detector pattern. The
	// detector scan below is the additional, tunable best-effort layer.
	if h.knownInText(in.SessionID, in.Prompt) {
		h.Last = Decision{Event: "UserPromptSubmit", Action: "block", Count: 1}
		return Output{
			Decision: "block",
			Reason:   "secrets-guard: prompt contains a known vault secret value",
			SystemMessage: "🛑 secrets-guard bloqueó el envío: el prompt contiene el valor de una contraseña de tu bóveda. " +
				"El modelo no debe ver contraseñas: ponla en un archivo .env local y deja que tus scripts la lean de ahí; nunca la pegues en el chat.",
		}
	}

	findings := h.eng.Scan(in.Prompt)
	if len(findings) == 0 || !h.cfg.BlockOnPromptSecret {
		h.Last = Decision{Event: "UserPromptSubmit", Action: "allow"}
		return Output{}
	}
	cats := categories(findings)
	h.Last = Decision{Event: "UserPromptSubmit", Action: "block", Categories: cats, Count: len(findings)}
	return Output{
		Decision: "block",
		Reason:   "secrets-guard: plaintext secret detected in prompt",
		SystemMessage: fmt.Sprintf(
			"🛑 secrets-guard bloqueó el envío: se detectó un posible secreto en texto plano (%s). "+
				"No pegues contraseñas ni claves en el chat — el modelo no debe ver el valor. "+
				"Ponla en un archivo .env local (p. ej. `DB_PASSWORD=...`); tus scripts la leen de ahí al "+
				"ejecutarse, pero el valor nunca llega al contexto del modelo.",
			strings.Join(cats, ", ")),
	}
}

// vaultHint returns guidance naming the active vault's reference syntax, so the
// user is told to use the vault they actually have installed.
func vaultHint(vaultName string) string {
	switch vaultName {
	case "keeper":
		return "Keeper — keeper://<UID>/field/password"
	case "1password":
		return "1Password — op://<vault>/<item>/<campo>"
	default:
		return "Keeper (keeper://<UID>/field/password) o 1Password (op://<vault>/<item>/<campo>)"
	}
}

func (h *Handler) handlePreTool(in Input) Output {
	if len(in.ToolInput) == 0 {
		h.Last = Decision{Event: "PreToolUse", Action: "allow"}
		return Output{}
	}

	joined := strings.Join(collectStrings(in.ToolInput), "\n")

	// 0) The model must never handle a resolved secret value directly. If the
	// tool input contains a value already resolved this session (in any
	// encoding), deny it — the model should use the reference instead.
	if h.knownInText(in.SessionID, joined) {
		h.Last = Decision{Event: "PreToolUse", Action: "deny"}
		return Output{HookSpecificOutput: &HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: "secrets-guard: la entrada contiene un valor de secreto ya resuelto en esta sesión. No manejes el valor en texto plano; usa la referencia de bóveda (op://… / keeper://…) y deja que el hook lo resuelva al ejecutar.",
		}}
	}

	// 1) A plaintext secret in the tool input (vault refs are ignored by detect).
	if findings := h.eng.Scan(joined); len(findings) > 0 {
		cats := categories(findings)
		switch h.cfg.ToolInputPolicy {
		case "warn":
			h.Last = Decision{Event: "PreToolUse", Action: "allow", Categories: cats, Count: len(findings)}
			return Output{SystemMessage: warnMsg(cats, h.cfg.VaultName)}
		case "redact":
			updated, _, _ := transformStrings(in.ToolInput, func(s string) (string, error) {
				out, _ := h.red.Redact(s)
				return out, nil
			})
			h.Last = Decision{Event: "PreToolUse", Action: "redact", Categories: cats, Count: len(findings)}
			return Output{HookSpecificOutput: &HookSpecificOutput{
				HookEventName: "PreToolUse", UpdatedInput: updated,
			}}
		default: // deny
			h.Last = Decision{Event: "PreToolUse", Action: "deny", Categories: cats, Count: len(findings)}
			return Output{HookSpecificOutput: &HookSpecificOutput{
				HookEventName:            "PreToolUse",
				PermissionDecision:       "deny",
				PermissionDecisionReason: warnMsg(cats, h.cfg.VaultName),
			}}
		}
	}

	// 2) Resolve vault references — ONLY for Bash (execution). For file/content
	// tools (Write, Edit, …) the reference is left in place on purpose, so the
	// value never lands in plaintext on disk. Within a Bash command, every
	// reference is resolved INTERNALLY (so its value can be redacted from the
	// output), but whether the value REPLACES the reference in the command is
	// controlled: by default references are injected; an occurrence escaped with a
	// leading backslash (\op://…) is kept literal; `command_references: keep`
	// keeps all literal; and commands that resolve references themselves
	// (op read, ksm secret notation, secrets-guard read, …) keep them literal too.
	var (
		resolvedVals []string
		resolvedRefs []string
		updated      json.RawMessage
		changed      bool
	)
	if h.isShellTool(in.ToolName) {
		var m map[string]any
		if json.Unmarshal(in.ToolInput, &m) == nil {
			if cmd, ok := m["command"].(string); ok && cmd != "" {
				// 1.5) The model must not resolve secrets itself: deny a command that
				// invokes the vault CLI (ksm/keeper/op) or `secrets-guard read|run`
				// directly. Only the sandbox-dlp service holds the vault credential and
				// renders references into the per-command mount; a direct CLI call would
				// pull plaintext values into the model's reach. (Defense in depth — the
				// credential is also withheld from every process but the service.)
				if reason, blocked := blockedVaultCLI(cmd); blocked {
					h.Last = Decision{Event: "PreToolUse", Action: "deny"}
					return Output{HookSpecificOutput: &HookSpecificOutput{
						HookEventName:            "PreToolUse",
						PermissionDecision:       "deny",
						PermissionDecisionReason: reason,
					}}
				}
				// Sandbox: wrap the WHOLE command in `secrets-guard sandbox`, which
				// renders vault references — in the environment AND in files under the
				// working directory — into real values inside an ephemeral per-command
				// mount namespace, then runs the command. The value never appears in the
				// command text, the shell, argv, or the transcript. Any command works
				// (pipes, &&, redirections, multi-line) because the original is passed
				// as a single quoted `sh -c` argument. On Cowork it also carries the
				// per-command trust anchor + one-time token.
				if h.cfg.SandboxMode {
					if rewritten, ok := h.sandboxWrapCommand(cmd, in.SessionID); ok {
						m["command"] = rewritten
						if b, e := json.Marshal(m); e == nil {
							h.Last = Decision{Event: "PreToolUse", Action: "sandbox"}
							return Output{HookSpecificOutput: &HookSpecificOutput{
								HookEventName: "PreToolUse", UpdatedInput: b,
							}}
						}
					}
				}
				newCmd, refs, vals, injErr := h.processBashCommand(cmd)
				if injErr != nil {
					h.Last = Decision{Event: "PreToolUse", Action: "deny", Count: 0}
					return Output{HookSpecificOutput: &HookSpecificOutput{
						HookEventName:            "PreToolUse",
						PermissionDecision:       "deny",
						PermissionDecisionReason: "secrets-guard: no se pudo resolver la referencia de bóveda: " + injErr.Error(),
					}}
				}
				resolvedVals, resolvedRefs = vals, refs
				if newCmd != cmd {
					m["command"] = newCmd
					if b, e := json.Marshal(m); e == nil {
						updated, changed = b, true
					}
				}
			}
		}
	}
	resolved := len(resolvedVals)
	if resolved > 0 {
		// Cache the values in the session daemon (memory only) and record the
		// references on disk (paths are not secret) so the value can be re-derived
		// if the daemon is ever unavailable. Both keep it out of later tool I/O.
		h.cache.Add(in.SessionID, resolvedVals)
		seen.RecordPaths(in.SessionID, resolvedRefs)
	}

	// In Cowork mode the host does not resolve inline, so populate the Cowork allowlist
	// with LEAST PRIVILEGE. The ONLY value channel into the VM is
	// `secrets-guard run --env-file .env`, so the only thing that needs authorizing
	// is a reference written as a `KEY=op://…` value into an env/dotenv file via the
	// Write/Edit tool. We deliberately do NOT authorize from:
	//   - bare Bash commands (a reference is kept literal and never fetched inline,
	//     so `echo op://victim` must not mint an allowlist entry — confused deputy);
	//   - arbitrary prose in a *.env file (only real KEY=ref lines count).
	// This bounds what any rogue/curious VM process can pull to exactly the secrets
	// the workflow declared in its env files.
	if h.cfg.CoworkMode && isEnvFileWrite(in.ToolName, in.ToolInput) {
		if refs := h.envFileRefs(in.ToolInput); len(refs) > 0 {
			seen.RecordPaths(in.SessionID, refs)
		}
	}

	// `injected` is true only when a value actually replaced a reference in the
	// command body (vs. resolved-internally-but-kept-literal, which still tracks
	// the value for output redaction but leaves the reference in place).
	injected := changed

	// 3) For Bash in redact mode, wrap the command so its output is redacted at
	// the source (PostToolUse output rewriting is not honored by Claude Code).
	wrapped := false
	if h.isShellTool(in.ToolName) && h.cfg.ToolOutputMode == "redact" && h.selfPath != "" && !h.cfg.CoworkMode && !h.cfg.SandboxMode {
		base := updated
		if base == nil {
			base = in.ToolInput
		}
		if w, ok := wrapBashCommand(base, h.selfPath, in.SessionID); ok {
			updated, changed, wrapped = w, true, true
		}
	}
	_ = changed

	switch {
	case injected && wrapped:
		h.Last = Decision{Event: "PreToolUse", Action: "inject+wrap", Count: resolved}
	case injected:
		h.Last = Decision{Event: "PreToolUse", Action: "inject", Count: resolved}
	case resolved > 0 && wrapped:
		h.Last = Decision{Event: "PreToolUse", Action: "track+wrap", Count: resolved}
	case resolved > 0:
		// References resolved internally for output redaction, but kept literal in
		// the command and no wrap applied — nothing to rewrite.
		h.Last = Decision{Event: "PreToolUse", Action: "track", Count: resolved}
		return Output{}
	case wrapped:
		h.Last = Decision{Event: "PreToolUse", Action: "wrap"}
	default:
		h.Last = Decision{Event: "PreToolUse", Action: "allow"}
		return Output{}
	}
	return Output{HookSpecificOutput: &HookSpecificOutput{
		HookEventName: "PreToolUse", UpdatedInput: updated,
	}}
}

// isShellTool reports whether tool_name is a command-execution (shell) tool whose
// `command` input should be wrapped by the sandbox and whose output should be
// redacted. It matches "Bash" (Claude Code), the MCP shell tools Cowork exposes
// (e.g. `mcp__workspace__bash`, `…__shell`) by suffix, a bare `bash`/`shell`, and
// any explicit names from the shell_tools option. It deliberately does NOT match
// helper tools like "BashOutput".
func (h *Handler) isShellTool(name string) bool {
	if name == "Bash" {
		return true
	}
	for _, t := range h.cfg.ShellTools {
		if name == t {
			return true
		}
	}
	l := strings.ToLower(name)
	return l == "bash" || l == "shell" ||
		strings.HasSuffix(l, "__bash") || strings.HasSuffix(l, "__shell")
}

func (h *Handler) handlePostTool(in Input) Output {
	if len(in.ToolResponse) == 0 {
		h.Last = Decision{Event: "PostToolUse", Action: "allow"}
		return Output{}
	}
	// Scan EVERY string leaf of the response, not just a top-level string. Bash
	// returns {stdout,stderr,…} and the Cowork MCP shell tool returns an MCP content
	// shape ({content:[{type:"text",text:…}]}) — walking all leaves catches a leaked
	// value regardless of the response shape.
	text := toText(in.ToolResponse)
	if structured := strings.Join(collectStrings(in.ToolResponse), "\n"); len(structured) > len(text) {
		text = structured
	}

	// A value resolved earlier this session reappearing in the output (in any
	// encoding) is a leak — e.g. the model read back a file the hook resolved
	// into, or a Bash command defeated the source-side redaction wrap. We ALWAYS
	// check here (including for wrapped Bash) as a server-side backstop: if the
	// wrap worked the output is already redacted and this finds nothing; if the
	// wrap was bypassed, the leak is blocked here.
	//
	// This backstop runs even when ToolOutputMode is "off". `off` disables the
	// HEURISTIC detector scan below (which can have false positives and is a
	// best-effort plus), but it must NOT disable the core invariant that a value
	// secrets-guard itself resolved this session never round-trips to the model.
	// In sandbox mode the inline redact-stream wrap is disabled, so this is the
	// ONLY thing standing between a rendered vault secret printed by a Bash command
	// and the transcript — gating it on ToolOutputMode would silently leak it.
	if h.knownInText(in.SessionID, text) {
		h.Last = Decision{Event: "PostToolUse", Action: "block", Count: 1}
		return Output{
			Decision: "block",
			Reason:   "secrets-guard: resolved secret present in tool output",
			SystemMessage: "🛑 secrets-guard retuvo la salida: contiene un secreto ya resuelto en esta sesión " +
				"(posible fuga al leerlo de vuelta). El valor no se entregó al modelo; usa la referencia de bóveda.",
		}
	}

	// Detector-based scanning/blocking of arbitrary (not session-resolved) secrets
	// is the tunable part: `off` disables it.
	if h.cfg.ToolOutputMode == "off" {
		h.Last = Decision{Event: "PostToolUse", Action: "allow"}
		return Output{}
	}

	findings := h.eng.Scan(text)
	if len(findings) == 0 {
		h.Last = Decision{Event: "PostToolUse", Action: "allow"}
		return Output{}
	}
	// Claude Code 2.1.x does not honor PostToolUse output rewriting, so the only
	// reliable client-side guarantee is to withhold the output. Bash output is
	// already redacted inline by the PreToolUse wrap; this is the safety net for
	// non-Bash tools (Read, Grep, ...) and for the block policy.
	cats := categories(findings)
	h.Last = Decision{Event: "PostToolUse", Action: "block", Categories: cats, Count: len(findings)}
	return Output{
		Decision: "block",
		Reason:   "secrets-guard: secret detected in tool output",
		SystemMessage: fmt.Sprintf(
			"🛑 secrets-guard retuvo la salida de la herramienta: contiene un secreto (%s). "+
				"El valor no se entregó al modelo. Usa una referencia de bóveda en lugar de exponer el secreto.",
			strings.Join(cats, ", ")),
	}
}

// wrapBashCommand rewrites a Bash tool_input so the command's stdout and stderr
// are piped through `secrets-guard redact-stream`, preserving the original exit
// code and stream separation. Returns the new tool_input and true on success.
// refWithEscapeRe matches a vault reference with an OPTIONAL leading backslash.
// The backslash opts that single occurrence out of value substitution
// (`\op://…` is kept literal as `op://…`). It mirrors vault.anyRefRe but captures
// the escape (group 1) and the reference (group 2) separately so each occurrence
// can be handled independently.
var refWithEscapeRe = regexp.MustCompile(`(\\?)((?i:keeper|op|akv)://[A-Za-z0-9._\-/\[\]?=&:@]+)`)

// isVaultResolverCommand reports whether the command itself resolves vault
// references (e.g. `op read`, `ksm secret notation`, `secrets-guard read/run`).
// For these the reference must stay LITERAL in the command — the tool consumes
// the reference, not the value (injecting the value would turn `op read op://…`
// into `op read <value>`, which fails). secrets-guard still resolves the
// reference internally so the command's output can be redacted.
func isVaultResolverCommand(cmd string) bool {
	for _, marker := range []string{
		"op read", "op inject", "op run",
		"ksm secret notation", "ksm exec",
		"secrets-guard read", "secrets-guard run",
	} {
		if strings.Contains(cmd, marker) {
			return true
		}
	}
	return false
}

// processBashCommand resolves every vault reference in a Bash command INTERNALLY
// (so each value can be tracked and redacted from the command's output) and
// returns the references found and the values resolved. Whether a value REPLACES
// its reference in the returned command is decided per occurrence:
//
//   - an occurrence escaped with a leading backslash (`\op://…`) is kept literal
//     (the backslash is stripped on the way out);
//   - when command_references=keep, or the command itself resolves references
//     (op read, ksm notation, secrets-guard read/run, …), ALL occurrences are
//     kept literal;
//   - otherwise the value is injected.
//
// If a value must be injected but fails to resolve, injectErr is returned so the
// caller can deny the action. References that are kept literal never produce an
// injectErr even if their internal resolution fails (the command resolves them
// itself, or the developer asked to keep them).
func (h *Handler) processBashCommand(cmd string) (newCmd string, refs []string, vals []string, injectErr error) {
	keepAll := h.cfg.CommandReferences == "keep" || isVaultResolverCommand(cmd)
	out := refWithEscapeRe.ReplaceAllStringFunc(cmd, func(match string) string {
		sub := refWithEscapeRe.FindStringSubmatch(match)
		escaped, ref := sub[1] == `\`, sub[2]
		refs = append(refs, ref)

		if h.cfg.CoworkMode {
			// Cowork: the tool runs in the VM. NEVER make the value shell-visible —
			// any value placed in the VM shell (even via $(secrets-guard read …))
			// can be redirected to the VM's disk (`… > .env`, heredoc, tee). Keep
			// EVERY reference literal; the value is delivered only through
			// `secrets-guard run --env-file` (rewritten to `cw-run`), which injects
			// it into the child process's environment (memory), never into the shell
			// or a file. The reference is recorded (by the caller) into the allowlist.
			return ref
		}

		// Local mode: always resolve internally so the value is tracked for output
		// redaction, even when the reference is kept literal in the command.
		resolved, rv, err := h.vault.ResolveString(ref)
		vals = append(vals, rv...)
		if escaped || keepAll {
			return ref // keep literal, stripping any opt-out backslash
		}
		if err != nil {
			if injectErr == nil {
				injectErr = err
			}
			return ref
		}
		return resolved
	})
	return out, refs, vals, injectErr
}

// vaultCLIRe matches a direct invocation of a vault CLI (Keeper's ksm/keeper-ksm,
// Keeper Commander, or 1Password's op) at a command position, followed by a subcommand
// that reads or manages secrets. The model must never call these itself — only the
// sandbox-dlp service may resolve references.
var vaultCLIRe = regexp.MustCompile(`(?i)(?:^|[\s;&|(` + "`" + `])(?:ksm|keeper-ksm|keeper|op)\s+(?:secret|profile|read|item|inject|get|notation|list|exec|init|run)\b`)

// sgResolveRe matches `secrets-guard read|run`, the CLI subcommands that themselves
// resolve a reference to a value (the sandbox path uses `secrets-guard sandbox`, which is
// not matched).
var sgResolveRe = regexp.MustCompile(`(?i)\bsecrets-guard\s+(?:read|run)\b`)

// blockedVaultCLI reports whether cmd invokes a vault CLI (or secrets-guard's resolving
// subcommands) directly, and the reason to return to the model.
func blockedVaultCLI(cmd string) (string, bool) {
	if vaultCLIRe.MatchString(cmd) || sgResolveRe.MatchString(cmd) {
		return "secrets-guard: no ejecutes el CLI de la bóveda (ksm/keeper/op) ni " +
			"`secrets-guard read|run` directamente — solo el servicio sandbox-dlp tiene la " +
			"credencial y resuelve secretos, sirviéndolos únicamente al subárbol del comando. " +
			"Usa la referencia (op://… / keeper://…) en un archivo de configuración y deja que " +
			"el sandbox la renderice al ejecutar el comando.", true
	}
	return "", false
}

// sandboxWrapCommand wraps an entire Bash command in `secrets-guard sandbox`, which
// renders vault references — in the environment AND in matched files under the
// working directory — into real values inside an ephemeral per-command mount
// namespace, then runs the original command. The original command is passed as a
// single quoted `sh -c '<cmd>'` argument, so ANY command works (pipes, &&,
// redirections, multi-line) and the secret never appears in the command text.
//
// On a Cowork host the wrapper also carries the per-command trust anchor (host
// public key + exec id, via the environment — authoritative over agent argv) and a
// one-time token on fd 3. On a local Linux host no anchor/token is needed (the
// sandbox resolves with the local vault).
func (h *Handler) sandboxWrapCommand(cmd, session string) (string, bool) {
	inner := "sh -c " + shellSingleQuote(cmd)

	if !h.cfg.CoworkMode {
		// Local Linux host: the sandbox resolves with the local vault. Pin SG_SESSION
		// on the sandbox's own command line (inline, not `export`, so the user CMD
		// cannot clobber it) so the sandbox records the rendered values in this
		// session's ledger — that is what lets the PostToolUse leak-block withhold a
		// rendered value if the command prints it. (In Cowork the host daemon records
		// values independently, so no SG_SESSION is needed there.)
		return "SG_SESSION=" + shellSingleQuote(session) +
			" secrets-guard sandbox -- " + inner, true
	}

	// Cowork: mint the per-command anchor + one-time token.
	if h.anchor == nil {
		return "", false
	}
	allowed := seen.LoadPaths(session)
	execID, hostPubB64, tokenB64, ok := h.anchor.Mint(session, allowed)
	if !ok {
		return "", false
	}
	var b strings.Builder
	// Non-secret anchor via the ENVIRONMENT (authoritative; agent argv cannot
	// override an env assignment in the command prefix). The one-time TOKEN stays on
	// fd 3 only. The redirect binds to the outer `secrets-guard sandbox` command.
	b.WriteString("SG_CW_HOSTPUB=")
	b.WriteString(shellSingleQuote(hostPubB64))
	b.WriteString(" SG_CW_EXECID=")
	b.WriteString(shellSingleQuote(execID))
	b.WriteString(" SG_CW_AUTHFD=3")
	if h.cfg.CoworkIsolate {
		b.WriteString(" SG_CW_ISOLATE=1")
	}
	b.WriteString(" secrets-guard sandbox -- ")
	b.WriteString(inner)
	b.WriteString(" 3<<<")
	b.WriteString(shellSingleQuote(tokenB64))
	return b.String(), true
}

func wrapBashCommand(toolInput json.RawMessage, selfPath, session string) (json.RawMessage, bool) {
	var m map[string]any
	if err := json.Unmarshal(toolInput, &m); err != nil {
		return nil, false
	}
	cmd, ok := m["command"].(string)
	if !ok || cmd == "" || strings.Contains(cmd, "secrets-guard redact-stream") {
		return nil, false
	}
	q := shellSingleQuote(selfPath)
	qs := shellSingleQuote(session)
	// Export SG_SESSION for the whole command so a `secrets-guard run` invoked
	// inside CMD can register the values it resolves. But CMD could clobber
	// SG_SESSION (`unset SG_SESSION; …`) to disable redaction, so the redact-stream
	// children get the session on their OWN command line (immune to CMD's env).
	m["command"] = "export SG_SESSION=" + qs + "; " +
		"__sg_o=$(mktemp); __sg_e=$(mktemp); { " + cmd + "; } >\"$__sg_o\" 2>\"$__sg_e\"; __sg_rc=$?; " +
		"SG_SESSION=" + qs + " " + q + " redact-stream <\"$__sg_o\"; " +
		"SG_SESSION=" + qs + " " + q + " redact-stream <\"$__sg_e\" >&2; " +
		"rm -f \"$__sg_o\" \"$__sg_e\"; exit $__sg_rc"
	b, err := json.Marshal(m)
	if err != nil {
		return nil, false
	}
	return b, true
}

// shellSingleQuote wraps s in single quotes, escaping embedded single quotes.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// isEnvFileWrite reports whether a Write/Edit tool writes to an env/dotenv file —
// the only file content from which the Cowork allowlist is populated. It is
// restricted to file-content tools so a Bash command cannot pose as an env-file
// write.
func isEnvFileWrite(toolName string, toolInput json.RawMessage) bool {
	// Only Write/Edit, whose content envFileRefs actually parses (content /
	// new_string). MultiEdit/NotebookEdit use different shapes; we deliberately do
	// NOT claim to authorize through them (fail-closed: the agent uses Write).
	switch toolName {
	case "Write", "Edit":
	default:
		return false
	}
	var m map[string]any
	if json.Unmarshal(toolInput, &m) != nil {
		return false
	}
	for _, k := range []string{"file_path", "path", "filePath", "notebook_path"} {
		if p, ok := m[k].(string); ok && looksLikeEnvFile(p) {
			return true
		}
	}
	return false
}

// looksLikeEnvFile matches .env, env, .env.<x> and *.env (case-insensitive).
func looksLikeEnvFile(path string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(path)))
	return base == ".env" || base == "env" ||
		strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env")
}

// envFileRefs extracts vault references that appear as the VALUE of a `KEY=value`
// line in the written content — never references in comments or prose — so only
// real env entries authorize the Cowork allowlist.
func (h *Handler) envFileRefs(toolInput json.RawMessage) []string {
	var m map[string]any
	if json.Unmarshal(toolInput, &m) != nil {
		return nil
	}
	content, _ := m["content"].(string)
	if content == "" {
		content, _ = m["new_string"].(string) // Edit / MultiEdit
	}
	var out []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		val := strings.Trim(strings.TrimSpace(line[eq+1:]), `"'`)
		out = append(out, h.vault.FindRefs(val)...)
	}
	return out
}

func warnMsg(cats []string, vaultName string) string {
	return fmt.Sprintf(
		"secrets-guard: se detectó un secreto en texto plano (%s) en la entrada de la herramienta. "+
			"Reemplázalo por una referencia de bóveda. Usa %s.",
		strings.Join(cats, ", "), vaultHint(vaultName))
}

func categories(fs []detect.Finding) []string {
	set := map[string]bool{}
	for _, f := range fs {
		set[string(f.Category)] = true
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// --- JSON helpers over arbitrary tool_input / tool_response shapes ---

// collectStrings returns every string leaf in a JSON value.
func collectStrings(raw json.RawMessage) []string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []string{string(raw)}
	}
	var out []string
	var walk func(any)
	walk = func(n any) {
		switch t := n.(type) {
		case string:
			out = append(out, t)
		case float64:
			// Numbers are leaves too: a purely numeric secret (PIN/token) placed as
			// a JSON number must still be seen by the known-value/detector checks.
			out = append(out, strconv.FormatFloat(t, 'f', -1, 64))
		case bool:
			out = append(out, strconv.FormatBool(t))
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				out = append(out, k) // object keys can carry a value too
				walk(t[k])
			}
		}
	}
	walk(v)
	return out
}

// transformStrings applies fn to every string leaf and re-marshals. The second
// return reports whether any string changed.
func transformStrings(raw json.RawMessage, fn func(string) (string, error)) (json.RawMessage, bool, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw, false, nil
	}
	changed := false
	var walk func(any) (any, error)
	walk = func(n any) (any, error) {
		switch t := n.(type) {
		case string:
			out, err := fn(t)
			if err != nil {
				return nil, err
			}
			if out != t {
				changed = true
			}
			return out, nil
		case []any:
			for i, e := range t {
				nv, err := walk(e)
				if err != nil {
					return nil, err
				}
				t[i] = nv
			}
			return t, nil
		case map[string]any:
			for k, e := range t {
				nv, err := walk(e)
				if err != nil {
					return nil, err
				}
				t[k] = nv
			}
			return t, nil
		default:
			return n, nil
		}
	}
	nv, err := walk(v)
	if err != nil {
		return raw, false, err
	}
	if !changed {
		return raw, false, nil
	}
	b, err := json.Marshal(nv)
	if err != nil {
		return raw, false, err
	}
	return b, true, nil
}

// toText renders a tool_response (which may be a JSON string or a structured
// object) as plain text for scanning/redaction.
func toText(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}
