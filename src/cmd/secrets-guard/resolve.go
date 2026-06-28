package main

import (
	"fmt"

	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// resolveRefsLocal resolves vault references with the LOCAL vault (the user's ksm/op
// profile). It returns an error ONLY when no vault is available at all (fail-closed on the
// whole batch). A single reference that fails to resolve is SKIPPED (omitted from the result
// map), not fatal — the caller decides how to degrade per reference, so one bad reference
// never aborts a command that also has good ones.
func resolveRefsLocal(cfg config.Config, refs []string) (map[string]string, error) {
	uniq := dedupe(refs)
	if len(uniq) == 0 {
		return map[string]string{}, nil
	}
	resolver, err := vault.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount)
	if err != nil {
		return nil, err
	}
	if resolver == nil || resolver.ProviderName() == "none" {
		return nil, fmt.Errorf("no hay una bóveda local para resolver las referencias " +
			"(inicializa tu perfil de bóveda: ksm profile init <token>)")
	}
	out := make(map[string]string, len(uniq))
	for _, ref := range uniq {
		v, vals, rerr := resolver.ResolveString(ref)
		if rerr != nil {
			continue // skip a reference that fails to resolve; the caller degrades per-ref
		}
		if len(vals) > 0 {
			out[ref] = vals[0]
		} else {
			out[ref] = v
		}
	}
	return out, nil
}

// hasLocalVault reports whether a local vault CLI is available to resolve values.
// It is false in the Cowork VM, where `read` must refuse (it would print a value to
// a shell that could redirect it to disk).
func hasLocalVault(cfg config.Config) bool {
	r, _ := vault.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount)
	return r != nil && r.ProviderName() != "none"
}

// dedupe removes empty/duplicate references preserving order.
func dedupe(in []string) []string {
	seenSet := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seenSet[s]; ok {
			continue
		}
		seenSet[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
