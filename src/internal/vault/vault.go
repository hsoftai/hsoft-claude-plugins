// Package vault resolves vault references (keeper://, op://) into secret values
// at tool-execution time, so the model only ever sees the reference. Keeper is
// the primary provider; 1Password mirrors it through the same Provider
// interface. Provider selection is first-found-wins (Keeper, then 1Password).
package vault

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Provider resolves a single reference of its scheme.
type Provider interface {
	Name() string   // "keeper" | "1password"
	Scheme() string // "keeper" | "op"
	Available() bool
	// Resolve returns the secret for ref. account is an optional per-reference
	// account override (e.g. parsed from op://<account>:vault/item/field);
	// providers that don't support accounts ignore it.
	Resolve(ref, account string) (string, error)
}

// Runner abstracts process execution for testability.
type Runner interface {
	Look(name string) bool
	Run(name string, args ...string) (string, error)
}

// execRunner is the production Runner backed by os/exec.
type execRunner struct{}

func (execRunner) Look(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (execRunner) Run(name string, args ...string) (string, error) {
	out, err := vaultCommand(name, args).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("%s failed: %s", name, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}

// NewRunner returns the production Runner.
func NewRunner() Runner { return execRunner{} }

// ExportKeeperConfig returns the base64 KSM_CONFIG of the local Keeper Secrets Manager
// profile (`ksm profile export --file-format json`). The sandbox-dlp service ingests this
// ONCE into its own protected store, then removes the local profile so that only the
// service — never a bare `ksm` invocation by any other process — can resolve references.
func ExportKeeperConfig() (string, error) {
	out, err := execRunner{}.Run("ksm", "profile", "export", "--file-format", "json")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// DeleteKeeperProfile removes the local Keeper Secrets Manager profile from OS-native
// storage (the Windows Credential Manager / keyring), so a bare `ksm` can no longer
// resolve. Only a holder of KSM_CONFIG (the service, from its protected store) can.
func DeleteKeeperProfile() error {
	_, err := execRunner{}.Run("ksm", "profile", "delete", "_default")
	return err
}

// VerifyKeeperConfig confirms the ambient KSM_CONFIG can reach Keeper by listing secret
// metadata (titles/UIDs, never values). The service uses it to gate the destructive
// profile delete, so removing the local profile can never strand it without a credential.
func VerifyKeeperConfig() error {
	_, err := execRunner{}.Run("ksm", "secret", "list")
	return err
}

// anyRefRe matches a reference of any known vault scheme.
// refChars covers the characters valid in a vault reference: path segments, the
// bracketed predicates of Keeper notation, and the ?attribute=… query of a
// 1Password reference. The ':' and '@' allow an optional account prefix
// (op://<account>:vault/item/field, where account may be an email). (Names with
// spaces are not supported in free text — use UUIDs or hyphenated names.)
const refChars = `[A-Za-z0-9._\-/\[\]?=&:@]+`

var anyRefRe = regexp.MustCompile(`(?i)(?:keeper|op|akv)://` + refChars)

// splitAccountRef parses an optional account prefix embedded right after the
// scheme: op://<account>:vault/item/field -> ("<account>", "op://vault/item/field").
// The account marker is the first ':' that appears before the first '/'. Returns
// ("", ref) when there is no account prefix.
func splitAccountRef(ref string) (account, clean string) {
	i := strings.Index(ref, "://")
	if i < 0 {
		return "", ref
	}
	scheme, rest := ref[:i+3], ref[i+3:]
	slash := strings.IndexByte(rest, '/')
	colon := strings.IndexByte(rest, ':')
	if colon >= 0 && (slash < 0 || colon < slash) {
		return rest[:colon], scheme + rest[colon+1:]
	}
	return "", ref
}

// Resolver replaces references of the active provider's scheme within a string.
type Resolver struct {
	provider Provider
	re       *regexp.Regexp
}

// ProviderName returns the active provider's name, or "none".
func (r *Resolver) ProviderName() string {
	if r.provider == nil {
		return "none"
	}
	return r.provider.Name()
}

// ResolveString replaces every reference of the active scheme with its value and
// returns the resolved values (so the caller can track them and prevent them
// from later leaking). If no provider is active but a reference is present, it
// returns an error so the caller can deny the action.
func (r *Resolver) ResolveString(s string) (string, []string, error) {
	if r.provider == nil {
		if anyRefRe.MatchString(s) {
			return s, nil, fmt.Errorf("no hay una bóveda disponible (instala/configura Keeper o 1Password) para resolver la referencia")
		}
		return s, nil, nil
	}

	var firstErr error
	var values []string
	out := r.re.ReplaceAllStringFunc(s, func(ref string) string {
		account, clean := splitAccountRef(ref)
		val, err := r.provider.Resolve(clean, account)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return ref
		}
		values = append(values, val)
		return val
	})
	if firstErr != nil {
		return s, nil, firstErr
	}
	return out, values, nil
}

// FindReferences returns every vault reference (any scheme) in s.
func FindReferences(s string) []string { return anyRefRe.FindAllString(s, -1) }

// FindRefs returns the references in s (method form for the resolver interface).
func (r *Resolver) FindRefs(s string) []string { return FindReferences(s) }

// ResolveValues resolves a list of references to their current values, in
// parallel, skipping any that fail. Used to re-derive a session's secret values
// in ephemeral memory (they are never stored) to check tool I/O for leaks.
func (r *Resolver) ResolveValues(refs []string) []string {
	if r.provider == nil || len(refs) == 0 {
		return nil
	}
	sem := make(chan struct{}, 8)
	type res struct{ v string }
	ch := make(chan res, len(refs))
	for _, ref := range refs {
		go func(ref string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			account, clean := splitAccountRef(ref)
			v, err := r.provider.Resolve(clean, account)
			if err != nil {
				v = ""
			}
			ch <- res{v}
		}(ref)
	}
	out := make([]string, 0, len(refs))
	for range refs {
		if rr := <-ch; rr.v != "" {
			out = append(out, rr.v)
		}
	}
	return out
}

// Select chooses a provider given the configured preference and a Runner.
//   - "keeper"     -> Keeper only
//   - "1password"  -> 1Password only
//   - "auto"       -> first available, Keeper preferred
//
// When the chosen/auto provider is unavailable, Resolver.provider is nil and
// references will error at resolve time. opAccount is passed to the 1Password
// provider for machines with multiple accounts (empty = let op decide).
func Select(pref string, runner Runner, opAccount string) (*Resolver, error) {
	keeper := newKeeper(runner)
	op := newOnePassword(runner, opAccount)

	var chosen Provider
	switch pref {
	case "keeper":
		if keeper.Available() {
			chosen = keeper
		}
	case "1password":
		if op.Available() {
			chosen = op
		}
	case "auto", "":
		switch {
		case keeper.Available():
			chosen = keeper
		case op.Available():
			chosen = op
		}
	default:
		return nil, fmt.Errorf("proveedor de bóveda desconocido: %q", pref)
	}

	r := &Resolver{provider: chosen}
	if chosen != nil {
		r.re = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(chosen.Scheme()) + `://` + refChars)
	}
	return r, nil
}
