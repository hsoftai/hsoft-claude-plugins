package vault

import (
	"encoding/json"
	"fmt"
)

// bulkMinLen is the shortest value worth preloading into the redaction guard. It is
// higher than the per-reference floor (seen.minLen = 4) on purpose: the bulk guard
// loads EVERY value in the vault — including usernames, short labels, and the like —
// so a too-low floor would redact common short strings across the whole transcript.
// Six bytes avoids that pathological over-redaction while still covering real secrets.
const bulkMinLen = 6

// AllSecretValues returns every secret VALUE the active vault exposes to the current
// credential — every field, custom field, and notes of every accessible record. It is
// the deliberate counterpart to internal/catalog (which returns only metadata, never a
// value): here the values ARE returned, exclusively so the redaction guard can hold
// them in the per-session in-memory cache and guarantee none reaches the model. The
// values are never written to disk by this function. Field LABELS, TYPES, TITLES and
// UIDs are intentionally excluded — only the secret material is collected — so the
// guard does not redact harmless metadata. Values shorter than bulkMinLen are dropped.
func AllSecretValues(r Runner, provider string) ([]string, error) {
	switch provider {
	case "keeper":
		return keeperAllValues(r)
	case "1password":
		return onePasswordAllValues(r)
	default:
		return nil, fmt.Errorf("unknown provider %q", provider)
	}
}

// collector de-duplicates collected values and enforces the length floor.
type collector struct {
	seen map[string]struct{}
	vals []string
}

func newCollector() *collector { return &collector{seen: map[string]struct{}{}} }

func (c *collector) add(s string) {
	if len(s) < bulkMinLen {
		return
	}
	if _, ok := c.seen[s]; ok {
		return
	}
	c.seen[s] = struct{}{}
	c.vals = append(c.vals, s)
}

// walk extracts every string leaf from an arbitrary JSON value (a field's `value`
// array may hold plain strings, or objects like a name/phone whose nested strings are
// equally secret material).
func (c *collector) walk(n any) {
	switch t := n.(type) {
	case string:
		c.add(t)
	case []any:
		for _, e := range t {
			c.walk(e)
		}
	case map[string]any:
		for _, e := range t {
			c.walk(e)
		}
	}
}

// keeperAllValues lists every record shared to the KSM application and collects the
// values of its fields/custom fields/notes (one `ksm secret get` per record).
func keeperAllValues(r Runner) ([]string, error) {
	out, err := r.Run("ksm", "secret", "list", "--json")
	if err != nil {
		return nil, err
	}
	var list []struct {
		UID string `json:"uid"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("ksm secret list: %w", err)
	}
	col := newCollector()
	for _, it := range list {
		if it.UID == "" {
			continue
		}
		raw, err := r.Run("ksm", "secret", "get", "--uid", it.UID, "--json")
		if err != nil {
			continue // skip a record we cannot read; never fail the whole preload
		}
		var rec struct {
			Fields []struct {
				Value []any `json:"value"`
			} `json:"fields"`
			Custom []struct {
				Value []any `json:"value"`
			} `json:"custom"`
			Notes string `json:"notes"`
		}
		if json.Unmarshal([]byte(raw), &rec) != nil {
			continue
		}
		for _, f := range rec.Fields {
			col.walk(f.Value)
		}
		for _, f := range rec.Custom {
			col.walk(f.Value)
		}
		col.add(rec.Notes)
	}
	return col.vals, nil
}

// onePasswordAllValues lists every item in reach and collects its field values
// (one `op item get` per item; values are present in the item JSON).
func onePasswordAllValues(r Runner) ([]string, error) {
	out, err := r.Run("op", "item", "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	var list []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("op item list: %w", err)
	}
	col := newCollector()
	for _, it := range list {
		if it.ID == "" {
			continue
		}
		raw, err := r.Run("op", "item", "get", "--format", "json", "--", it.ID)
		if err != nil {
			continue
		}
		var rec struct {
			Fields []struct {
				Value string `json:"value"`
			} `json:"fields"`
		}
		if json.Unmarshal([]byte(raw), &rec) != nil {
			continue
		}
		for _, f := range rec.Fields {
			col.add(f.Value)
		}
	}
	return col.vals, nil
}
