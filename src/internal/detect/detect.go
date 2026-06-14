// Package detect implements the always-on, dependency-free secret detection
// layer of secrets-guard.
//
// Design rule: ZERO false positives. Detection is a best-effort *plus* on top of
// the core feature (vault reference resolution), and must never block a
// developer because some source code, identifier or value happened to match a
// loose pattern. Therefore this layer only matches secrets whose structure is
// effectively unambiguous — a reserved unique prefix (AKIA…, ghp_…, sk-ant-…) or
// a strict keyword+format combination (aws_secret_access_key = <40 base64>). We
// deliberately accept false negatives (missing some secrets) over any false
// positive. Catch-all heuristics (natural-language "password is X", generic
// key=value, credential URLs, entropy/token guessing) are intentionally NOT
// included — they belong, if anywhere, in opt-in custom_patterns.
//
// Vault references (keeper://, op://, akv://) are the *safe* form a developer is
// expected to use, so any match overlapping a vault reference is discarded.
package detect

import (
	"regexp"
	"sort"
)

// Finding is a single detected secret within scanned text. Value is the exact
// substring text[Start:End], suitable for redaction.
type Finding struct {
	Category Category
	Value    string
	Start    int
	End      int
}

// rule is a single detection pattern. valueGroup selects which capture group
// holds the actual secret value (0 = whole match).
type rule struct {
	cat        Category
	re         *regexp.Regexp
	valueGroup int
}

// Engine holds the compiled ruleset. It is safe for concurrent use once built;
// AddPattern/AddAllowlistPattern must be called during setup, before scanning.
type Engine struct {
	rules      []rule
	vaultRefRe *regexp.Regexp
	allow      []*regexp.Regexp
}

// AddPattern registers an additional detection rule under a custom category.
func (e *Engine) AddPattern(cat Category, pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	e.rules = append(e.rules, rule{cat: cat, re: re, valueGroup: 0})
	return nil
}

// AddAllowlistPattern registers a pattern; any finding whose value matches it is
// suppressed (used to silence known false positives / sample values).
func (e *Engine) AddAllowlistPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	e.allow = append(e.allow, re)
	return nil
}

func (e *Engine) allowed(value string) bool {
	for _, re := range e.allow {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// vaultRefPattern matches the safe reference form used by supported vaults.
const vaultRefPattern = `(?i)(?:keeper|op|akv|azurekeyvault|vault)://[^\s"']+`

// New returns an Engine with the default zero-false-positive ruleset. Every rule
// matches either a reserved unique token prefix or a strict keyword+format
// combination, so a normal identifier, path or sentence cannot trigger it.
func New() *Engine {
	rules := []rule{
		// Reserved unique prefixes — cannot collide with normal code or prose.
		{CategoryAWSAccessKey, regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b`), 0},
		{CategoryGCPAPIKey, regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), 0},
		{CategoryGitHubToken, regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b`), 0},
		{CategorySlackToken, regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), 0},
		{CategoryStripeKey, regexp.MustCompile(`\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b`), 0},
		{CategoryAnthropicKey, regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`), 0},
		// Structurally unambiguous blocks/tokens.
		{CategoryPrivateKey, regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`), 0},
		{CategoryJWT, regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`), 0},
		// Strict keyword + exact value format — the keyword makes a chance match
		// impossible, the fixed-length base64 value makes the whole thing a secret.
		{CategoryAWSSecretKey, regexp.MustCompile(`(?i)aws_?secret(?:_access)?_?key["' ]*[:=]["' ]*([A-Za-z0-9/+=]{40})`), 1},
		{CategoryAzureStorageKey, regexp.MustCompile(`(?i)AccountKey=([A-Za-z0-9+/=]{86,88})`), 1},
	}
	return &Engine{
		rules:      rules,
		vaultRefRe: regexp.MustCompile(vaultRefPattern),
	}
}

// Scan returns all secret findings in text, sorted by start offset and
// non-overlapping, excluding any match that overlaps a vault reference.
func (e *Engine) Scan(text string) []Finding {
	vaultSpans := e.vaultRefRe.FindAllStringIndex(text, -1)

	var out []Finding
	for _, r := range e.rules {
		for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := m[0], m[1]
			if r.valueGroup > 0 {
				gs, ge := m[2*r.valueGroup], m[2*r.valueGroup+1]
				if gs < 0 {
					continue
				}
				start, end = gs, ge
			}
			if overlapsAny(start, end, vaultSpans) {
				continue
			}
			if e.allowed(text[start:end]) {
				continue
			}
			out = append(out, Finding{
				Category: r.cat,
				Value:    text[start:end],
				Start:    start,
				End:      end,
			})
		}
	}

	out = dedupe(out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].End > out[j].End
	})

	// Drop overlapping spans (greedy, keeping the earliest/longest) so that
	// redaction can safely replace each span without shifting the others.
	nonOverlap := out[:0]
	lastEnd := -1
	for _, f := range out {
		if f.Start < lastEnd {
			continue
		}
		nonOverlap = append(nonOverlap, f)
		lastEnd = f.End
	}
	return nonOverlap
}

func overlapsAny(start, end int, spans [][]int) bool {
	for _, s := range spans {
		if start < s[1] && s[0] < end {
			return true
		}
	}
	return false
}

// dedupe removes findings with identical spans, keeping the first (rule order
// gives precedence to more specific patterns).
func dedupe(fs []Finding) []Finding {
	type key struct {
		s, e int
	}
	seen := make(map[key]bool, len(fs))
	out := fs[:0]
	for _, f := range fs {
		k := key{f.Start, f.End}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}
