// Package hook implements the Claude Code hook contracts for secrets-guard.
// A single Handler dispatches on hook_event_name and produces the exact JSON
// decision each event expects:
//
//   - UserPromptSubmit: block a prompt that contains a plaintext secret.
//   - PreToolUse:       resolve vault references into the tool input
//     (updatedInput) so the model never sees the value; deny a tool call that
//     carries a plaintext secret; and deny a Read whose target file contains a
//     vault value (Claude Code cannot rewrite Read's structured output, so the
//     read is blocked before it runs).
//   - PostToolUse:      block a tool result that leaked a known vault value, and
//     redact/block detector-matched secrets per tool_output_mode.
package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	// CoworkMode is true on a Cowork host (the agent's tools run in a VM). secrets-guard is
	// INERT in Cowork — it does not inspect, redact, deny, or rewrite anything — so the only
	// effect of this flag is to short-circuit Handle to a no-op. Cowork value-delivery is out
	// of scope for now and handled separately.
	CoworkMode bool
	// ShellTools are extra tool names (beyond "Bash" and the built-in MCP shell
	// pattern) to treat as command-execution tools, from the shell_tools option.
	ShellTools []string
	// RequireGuard makes the known-value redaction guard FAIL CLOSED: when the value
	// store is unavailable (the per-session in-memory cache could not be loaded from the
	// local ksm/op profile), a prompt, tool input, or tool output cannot be cleared
	// and is blocked instead of allowed. Set where the guard is mandatory, so a vault that
	// fails to load can never silently let a secret reach the model.
	RequireGuard bool
	// GuardReady is false when a vault IS configured but its values could not be loaded into
	// the cache (e.g. the ksm/op profile failed to load). In that state the guard cannot
	// verify a tool output is free of vault secrets, so PostToolUse BLOCKS the result rather
	// than risk showing one in plain text — "if a redact is not possible, block the read."
	// It is true when the vault is loaded (redaction works) or no vault is configured at all
	// (degrade to the pattern detector, do not block usage).
	GuardReady bool
	// RequireVault, when true (the default), BLOCKS a prompt with onboarding instructions when
	// NO vault is configured at all (VaultName == "none"). Set false (require_vault=off) to
	// allow use without a vault. It only gates the no-vault onboarding block.
	RequireVault bool
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
	selfPath string // absolute path to this binary, used for Bash output wrapping

	// Last holds the audit record of the most recent Handle call.
	Last Decision
}

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
	s, _ := h.checkGuard(session, text)
	return s == guardHit
}

// guardStatus is the outcome of checking a text against the known-value guard.
type guardStatus int

const (
	guardClean       guardStatus = iota // verified: no known secret value present
	guardHit                            // a known secret value is present (block/deny/redact)
	guardUnavailable                    // could NOT verify (store down) and no fallback — fail closed
)

// checkGuard reports whether text carries a resolved/known secret value, AND returns the
// text with every such value redacted (for in-place censoring of tool output). A cache HIT
// is authoritative (a positive is never an amnesiac false negative). On a cache MISS we
// corroborate against the durable reference ledger. When the cache is UNAVAILABLE: without
// a mandatory guard we fall back to the ledger; with RequireGuard set we cannot verify, so
// we return guardUnavailable and the caller fails closed. The redacted string equals the
// original text when nothing matched.
func (h *Handler) checkGuard(session, text string) (guardStatus, string) {
	found, redacted, ok := h.cache.Scan(session, text)
	if ok {
		if found {
			return guardHit, redacted
		}
		return guardClean, text // cache authoritative
	}
	// Cache unavailable.
	if h.cfg.RequireGuard {
		return guardUnavailable, text
	}
	if red, n := seen.Redact(text, h.sessionValues(session)); n > 0 {
		return guardHit, red
	}
	return guardClean, text
}

// guardUnavailableOutput is the fail-closed decision when the mandatory redaction guard
// cannot verify a text (the per-session value cache could not be loaded from the vault).
func guardUnavailableBlock(event string) Output {
	msg := "🛑 secrets-guard: no se pudo verificar el texto contra la bóveda (el perfil ksm/op " +
		"no está disponible) y guard_required=on exige garantía, así que se bloquea por seguridad " +
		"(fail-closed). Inicializa tu perfil de bóveda (ksm/op) y reintenta, o usa guard_required=auto."
	if event == "PreToolUse" {
		return Output{HookSpecificOutput: &HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: msg,
		}}
	}
	return Output{Decision: "block", Reason: "secrets-guard: DLP guard unavailable (fail-closed)", SystemMessage: msg}
}

// Handle routes an Input to the matching event handler.
func (h *Handler) Handle(in Input) Output {
	// secrets-guard operates ONLY in Claude Code (local). In Cowork (the agent's tools run
	// in a VM) the plugin stays completely INERT — it does not inspect, redact, deny, or
	// rewrite anything, even if the user installed and enabled it. Cowork value-delivery is
	// out of scope for now and will be handled separately.
	if h.cfg.CoworkMode {
		h.Last = Decision{Event: in.HookEventName, Action: "allow"}
		return Output{}
	}
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
	// Onboarding gate: with require_vault on (default) and NO vault configured at all, block
	// the prompt and tell the user how to set up Keeper. This makes the guard's protection a
	// precondition for use; set require_vault=off to allow use without a vault.
	if h.cfg.RequireVault && (h.cfg.VaultName == "" || h.cfg.VaultName == "none") {
		h.Last = Decision{Event: "UserPromptSubmit", Action: "block"}
		return Output{
			Decision:      "block",
			Reason:        "secrets-guard: no vault configured (require_vault on)",
			SystemMessage: keeperOnboardingMessage(),
		}
	}

	// Core invariant (always on, independent of BlockOnPromptSecret): a prompt must
	// never carry a real vault secret value into the model's context. With the
	// proactive guard, every vault value is preloaded into the session cache, so this
	// blocks a pasted secret even when it matches no heuristic detector pattern. The
	// detector scan below is the additional, tunable best-effort layer.
	switch s, _ := h.checkGuard(in.SessionID, in.Prompt); s {
	case guardHit:
		h.Last = Decision{Event: "UserPromptSubmit", Action: "block", Count: 1}
		return Output{
			Decision: "block",
			Reason:   "secrets-guard: prompt contains a known vault secret value",
			SystemMessage: "🛑 secrets-guard bloqueó el envío: el prompt contiene el valor de una contraseña de tu bóveda. " +
				"El modelo no debe ver contraseñas: ponla en un archivo .env local y deja que tus scripts la lean de ahí; nunca la pegues en el chat.",
		}
	case guardUnavailable:
		h.Last = Decision{Event: "UserPromptSubmit", Action: "block"}
		return guardUnavailableBlock("UserPromptSubmit")
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

// keeperOnboardingMessage is shown when require_vault is on and no vault is configured. It
// tells the user exactly how to set Keeper up so `secrets-guard install` can finish.
func keeperOnboardingMessage() string {
	return "🛑 secrets-guard: tu bóveda no está configurada, así que el uso está bloqueado hasta " +
		"completarla (puedes desactivar esto con require_vault=off).\n\n" +
		"Para habilitarlo con Keeper:\n" +
		"  1. En Keeper, crea una Carpeta Compartida (Shared Folder).\n" +
		"  2. En Keeper Secrets Manager, crea una Aplicación y asóciale esa carpeta compartida.\n" +
		"  3. Genera un token de un solo uso (one-time token) de esa aplicación.\n" +
		"  4. Ejecuta en una terminal:  secrets-guard install\n" +
		"     Te pedirá el token de forma interactiva, instalará el CLI de Keeper si falta, " +
		"inicializará el perfil y validará la conexión.\n" +
		"  5. Reinicia Claude Code (terminal nueva) y vuelve a intentarlo."
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
	switch s, _ := h.checkGuard(in.SessionID, joined); s {
	case guardHit:
		h.Last = Decision{Event: "PreToolUse", Action: "deny"}
		return Output{HookSpecificOutput: &HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: "secrets-guard: la entrada contiene un valor de secreto ya resuelto en esta sesión. No manejes el valor en texto plano; usa la referencia de bóveda (op://… / keeper://…) y deja que el hook lo resuelva al ejecutar.",
		}}
	case guardUnavailable:
		h.Last = Decision{Event: "PreToolUse", Action: "deny"}
		return guardUnavailableBlock("PreToolUse")
	}

	// 0.5) File-reading tools (Read) return the file CONTENT, which Claude Code does NOT let
	// a PostToolUse hook rewrite: updatedToolOutput is not applied to Read's structured
	// result in CC 2.1.x, so a vault value in the file would reach the model uncensored, and
	// (unlike Bash) there is no command to wrap at the source. The robust control is to DENY
	// the read before it runs when the target file contains a vault value — the content is
	// never produced. Files without a vault value read normally. Only runs when a vault is
	// configured (nothing to protect otherwise, and it avoids the file I/O cost).
	if h.cfg.VaultName != "" && h.cfg.VaultName != "none" && isFileReadTool(in.ToolName) {
		if out, handled := h.guardFileRead(in); handled {
			return out
		}
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
		updated json.RawMessage
		changed bool
		refs    []string
		nInject int
	)
	if h.isShellTool(in.ToolName) {
		var m map[string]any
		if json.Unmarshal(in.ToolInput, &m) == nil {
			if cmd, ok := m["command"].(string); ok && cmd != "" {
				// 1.5) The model must not resolve secrets itself: deny a command that
				// invokes the vault CLI (ksm/keeper/op) directly — its output would pull a
				// plaintext value into the model's reach, defeating redaction. The model
				// should put the reference in a config/.env and run it via the wrapper.
				if reason, blocked := blockedVaultCLI(cmd); blocked {
					h.Last = Decision{Event: "PreToolUse", Action: "deny"}
					return Output{HookSpecificOutput: &HookSpecificOutput{
						HookEventName:            "PreToolUse",
						PermissionDecision:       "deny",
						PermissionDecisionReason: reason,
					}}
				}
				// Replace each injectable reference with a ${SG_REF_n} placeholder and wrap
				// the command in `SG_REF_n='<ref>' secrets-guard run -- sh -c '<cmd>'`, which
				// resolves the reference and injects the real value ONLY into the child
				// process environment — never into the command body, argv, the shell, the
				// transcript, or disk. The value therefore never reaches the model NOR Claude
				// Code's permission classifier (which evaluates this rewritten command after
				// the hook); the classifier only ever sees the reference and the placeholder.
				inner, refPairs, found := h.processBashCommand(cmd)
				refs = found
				nInject = len(refPairs)
				switch {
				case nInject > 0:
					m["command"] = h.envInjectWrap(inner, refPairs)
					if b, e := json.Marshal(m); e == nil {
						updated, changed = b, true
					}
				case inner != cmd:
					// Only kept-literal occurrences changed the text (e.g. a `\op://…`
					// opt-out backslash was stripped). Emit the cleaned command verbatim
					// (no value injected); output redaction still wraps it below.
					m["command"] = inner
					if b, e := json.Marshal(m); e == nil {
						updated, changed = b, true
					}
				}
			}
		}
	}
	// Record the references used (paths are not secret) so a value the command later prints
	// can be re-derived for output redaction if the in-memory cache is cold.
	if len(refs) > 0 {
		seen.RecordPaths(in.SessionID, refs)
	}
	injected := changed

	// 3) For Bash in redact mode, wrap the command so its output is redacted at the source
	// (Claude Code does not honor PostToolUse output rewriting for tool results).
	wrapped := false
	if h.isShellTool(in.ToolName) && h.cfg.ToolOutputMode == "redact" && h.selfPath != "" {
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
		h.Last = Decision{Event: "PreToolUse", Action: "inject+wrap", Count: nInject}
	case injected:
		h.Last = Decision{Event: "PreToolUse", Action: "inject", Count: nInject}
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
	switch status, redacted := h.checkGuard(in.SessionID, text); status {
	case guardHit:
		// A confirmed vault value reached this tool output despite the source-side measures
		// (PreToolUse deny for Read, redact-stream wrap for Bash). BLOCK it rather than try to
		// redact in place: Claude Code does NOT reliably apply PostToolUse updatedToolOutput
		// (it is ignored for Read's structured result, and unconfirmed for others), so a
		// redacted string could silently fail and leak the value. `decision: "block"` is the
		// CC-sanctioned suppression. We still compute `redacted` to surface a value-free
		// systemMessage. (For Read this case never fires — the read was denied beforehand.)
		_ = redacted
		h.Last = Decision{Event: "PostToolUse", Action: "block", Count: 1}
		return Output{
			Decision: "block",
			Reason:   "secrets-guard: la salida contiene un valor de secreto de la bóveda y se bloqueó (no se puede redactar de forma fiable la salida de una herramienta en esta versión de Claude Code).",
			SystemMessage: "🛑 secrets-guard bloqueó la salida de la herramienta: contenía un valor de la bóveda. " +
				"Usa la referencia (keeper://… / op://…) en vez del valor.",
		}
	case guardUnavailable:
		h.Last = Decision{Event: "PostToolUse", Action: "block"}
		return guardUnavailableBlock("PostToolUse")
	}

	// The vault scan said "clean", but if the vault is configured yet its values could not be
	// loaded (GuardReady false), that "clean" is unverifiable — we could not have matched a
	// vault secret. Per the "no redact -> block read" policy we BLOCK rather than risk showing
	// a secret in plain text. This is FAIL-CLOSED and therefore gated on RequireGuard
	// (guard_required=on): with the default guard_required=auto we degrade to the detector
	// instead of blocking every tool output, so a machine whose vault is momentarily not
	// loaded is not bricked. Only applies when a vault is actually configured.
	if h.cfg.RequireGuard && !h.cfg.GuardReady && h.cfg.VaultName != "" && h.cfg.VaultName != "none" {
		h.Last = Decision{Event: "PostToolUse", Action: "block"}
		return Output{
			Decision: "block",
			Reason:   "secrets-guard: vault not loaded — cannot verify output is secret-free",
			SystemMessage: "🛑 secrets-guard retuvo la salida: tu bóveda está configurada pero no se " +
				"pudieron cargar sus valores, así que no se puede garantizar que la salida no contenga un " +
				"secreto. Corrige tu perfil (revisa `secrets-guard doctor`) y reintenta.",
		}
	}

	// Detector-based scanning of arbitrary (not vault-known) secrets is the tunable part:
	// `off` disables it.
	if h.cfg.ToolOutputMode == "off" {
		h.Last = Decision{Event: "PostToolUse", Action: "allow"}
		return Output{}
	}

	findings := h.eng.Scan(text)
	if len(findings) == 0 {
		h.Last = Decision{Event: "PostToolUse", Action: "allow"}
		return Output{}
	}
	cats := categories(findings)
	if h.cfg.ToolOutputMode == "block" {
		h.Last = Decision{Event: "PostToolUse", Action: "block", Categories: cats, Count: len(findings)}
		return Output{
			Decision: "block",
			Reason:   "secrets-guard: secret detected in tool output",
			SystemMessage: fmt.Sprintf(
				"🛑 secrets-guard retuvo la salida de la herramienta: contiene un secreto (%s). "+
					"El valor no se entregó al modelo.", strings.Join(cats, ", ")),
		}
	}
	// Default: redact the detected secrets in place so the model sees a censored output.
	red, _ := h.red.Redact(text)
	h.Last = Decision{Event: "PostToolUse", Action: "redact", Categories: cats, Count: len(findings)}
	return Output{HookSpecificOutput: &HookSpecificOutput{
		HookEventName:     "PostToolUse",
		UpdatedToolOutput: red,
	}}
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

// processBashCommand rewrites a Bash command so vault references are provisioned via the
// child ENVIRONMENT rather than injected inline. Each injectable reference is replaced with a
// ${SG_REF_n} placeholder, and the (name, reference) pairs are returned for the caller to
// pass to `secrets-guard run`. The decision per occurrence:
//
//   - an occurrence escaped with a leading backslash (`\op://…`) is kept literal
//     (the backslash is stripped on the way out);
//   - when command_references=keep, or the command itself resolves references
//     (op read, ksm notation, secrets-guard read, …), ALL occurrences are kept literal;
//   - otherwise a ${SG_REF_n} placeholder is emitted.
//
// refs lists every reference seen (for output-redaction tracking). No value is resolved here;
// resolution happens in `secrets-guard run` at execution time.
func (h *Handler) processBashCommand(cmd string) (newCmd string, refPairs [][2]string, refs []string) {
	keepAll := h.cfg.CommandReferences == "keep" || isVaultResolverCommand(cmd)
	n := 0
	out := refWithEscapeRe.ReplaceAllStringFunc(cmd, func(match string) string {
		sub := refWithEscapeRe.FindStringSubmatch(match)
		escaped := sub[1] == `\`
		// Trim a trailing unbalanced ']' (etc.) the greedy regex over-captured but that is
		// not part of the reference — e.g. `keeper://UID/field/password]` where the ] closes
		// surrounding shell/markdown, not Keeper [index] notation. The remainder stays literal.
		ref, rest := splitRefBoundary(sub[2])
		refs = append(refs, ref)
		if escaped || keepAll {
			return ref + rest // keep literal (the backslash opt-out is stripped)
		}
		name := fmt.Sprintf("SG_REF_%d", n)
		n++
		refPairs = append(refPairs, [2]string{name, ref})
		// The value is injected into the child env by `secrets-guard run`; the command body
		// only ever references it as ${SG_REF_n}, so no plaintext lands in the command text.
		return `"${` + name + `}"` + rest
	})
	return out, refPairs, refs
}

// splitRefBoundary trims trailing characters the greedy reference regex over-captured but
// that are not part of the reference: an UNBALANCED ']' (Keeper notation uses balanced
// [index], so a `]` with no matching `[` is a surrounding delimiter). Returns the clean
// reference and the trimmed remainder, which the caller keeps literal in the command.
func splitRefBoundary(ref string) (clean, rest string) {
	clean = ref
	for len(clean) > 0 && clean[len(clean)-1] == ']' &&
		strings.Count(clean, "]") > strings.Count(clean, "[") {
		clean = clean[:len(clean)-1]
	}
	return clean, ref[len(clean):]
}

// envInjectWrap builds the value-provisioning wrapper for a Bash command that contains vault
// references. Each reference is passed as an environment assignment SG_REF_n='<ref>' on a
// `secrets-guard run` invocation, which resolves it and injects the real value into the child
// process environment; the command body (under `sh -c`) refers to it only as ${SG_REF_n}.
// The plaintext value therefore never appears in the command text seen by Claude Code's
// permission classifier, the shell, argv, the transcript, or disk.
func (h *Handler) envInjectWrap(inner string, refPairs [][2]string) string {
	self := h.selfPath
	if self == "" {
		self = "secrets-guard"
	}
	var b strings.Builder
	for _, p := range refPairs {
		b.WriteString(p[0])
		b.WriteByte('=')
		b.WriteString(shellSingleQuote(p[1]))
		b.WriteByte(' ')
	}
	b.WriteString(shellSingleQuote(self))
	b.WriteString(" run -- sh -c ")
	b.WriteString(shellSingleQuote(inner))
	return b.String()
}

// vaultCLIRe matches a direct invocation of a vault CLI (Keeper's ksm/keeper-ksm,
// Keeper Commander, or 1Password's op) at a command position, followed by a subcommand
// that reads or manages secrets. The model must never call these itself — resolution
// happens inside the sandbox/hook, never in a command whose output reaches the model.
var vaultCLIRe = regexp.MustCompile(`(?i)(?:^|[\s;&|(` + "`" + `])(?:ksm|keeper-ksm|keeper|op)\s+(?:secret|profile|read|item|inject|get|notation|list|exec|init|run)\b`)

// sgResolveRe matches `secrets-guard read`, which prints a resolved value to stdout (the
// model could redirect it to a file). It is DENIED. `secrets-guard run` is deliberately NOT
// matched: it injects resolved values only into the child process ENVIRONMENT (never stdout,
// argv, or the command body) and its output stays under the redaction wrap, so the model may
// use it to run a tool that needs real values from a .env without ever seeing them.
var sgResolveRe = regexp.MustCompile(`(?i)\bsecrets-guard\s+read\b`)

// isFileReadTool reports whether a tool returns raw file content to the model as a
// structured result that PostToolUse cannot rewrite (so a vault value in the file must be
// blocked at PreToolUse instead of redacted afterwards). The built-in Read is the case.
func isFileReadTool(name string) bool {
	return name == "Read"
}

// maxScanFileSize caps how much of a file the read-guard inspects. Files holding secrets
// (.env, config, notes) are tiny; the cap only bounds work on pathologically large files.
const maxScanFileSize = 8 << 20 // 8 MiB

// guardFileRead inspects the file a Read is about to return and, if its content contains a
// vault value (in any encoding), DENIES the read so the value never reaches the model. It
// returns (output, true) when it produced a decision, or (zero, false) to let normal
// processing continue (file unreadable/binary/empty, or no vault value present).
func (h *Handler) guardFileRead(in Input) (Output, bool) {
	var m struct {
		FilePath string `json:"file_path"`
	}
	if json.Unmarshal(in.ToolInput, &m) != nil || m.FilePath == "" {
		return Output{}, false
	}
	content, ok := readFileForScan(m.FilePath)
	if !ok {
		return Output{}, false // unreadable, binary, empty, or oversized — let Read handle it
	}
	switch s, _ := h.checkGuard(in.SessionID, content); s {
	case guardHit:
		h.Last = Decision{Event: "PreToolUse", Action: "deny", Count: 1}
		return Output{HookSpecificOutput: &HookSpecificOutput{
			HookEventName:      "PreToolUse",
			PermissionDecision: "deny",
			PermissionDecisionReason: "secrets-guard: el archivo \"" + m.FilePath + "\" contiene un valor de " +
				"secreto de la bóveda. Esta versión de Claude Code no permite redactar la salida de Read, así " +
				"que la lectura se bloquea por seguridad para que el valor no llegue al modelo. Usa la referencia " +
				"de bóveda (keeper://… / op://…) en vez del valor, o consulta el campo por su referencia.",
		}}, true
	case guardUnavailable:
		h.Last = Decision{Event: "PreToolUse", Action: "deny"}
		return guardUnavailableBlock("PreToolUse"), true
	}
	return Output{}, false // no vault value in the file — allow the read
}

// readFileForScan returns up to maxScanFileSize bytes of a text file for scanning, or
// ok=false when the path is unreadable, a directory, empty, or appears to be binary (a NUL
// byte) — cases where Read would not surface plaintext the guard needs to inspect.
func readFileForScan(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || fi.IsDir() {
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxScanFileSize))
	if err != nil || len(b) == 0 {
		return "", false
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return "", false // binary
	}
	return string(b), true
}

// blockedVaultCLI reports whether cmd invokes a vault CLI (or secrets-guard's resolving
// subcommands) directly, and the reason to return to the model.
func blockedVaultCLI(cmd string) (string, bool) {
	if vaultCLIRe.MatchString(cmd) || sgResolveRe.MatchString(cmd) {
		return "secrets-guard: no ejecutes el CLI de la bóveda (ksm/keeper/op) ni " +
			"`secrets-guard read` directamente — eso traería el valor en texto plano al " +
			"contexto del modelo y rompería la redacción. " +
			"Para que una app consuma valores de un .env sin verlos, usa " +
			"`secrets-guard run --env-file <archivo> -- <comando>`: resuelve las referencias " +
			"al ENTORNO del proceso hijo y la salida sigue redactada.", true
	}
	return "", false
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
