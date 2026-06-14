package seen

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// variants returns the secret value plus every reversible encoding of it we
// guard against, so a value cannot slip through re-encoded (base64, hex, base32,
// URL-escaped, JSON-escaped, raw bits). Each variant is at least minLen long.
func variants(v string) []string {
	if len(v) < minLen {
		return nil
	}
	b := []byte(v)
	set := make(map[string]struct{}, 16)
	add := func(s string) {
		if len(s) >= minLen {
			set[s] = struct{}{}
		}
	}

	add(v) // raw

	// base64 (standard + URL-safe, padded + unpadded)
	add(base64.StdEncoding.EncodeToString(b))
	add(base64.RawStdEncoding.EncodeToString(b))
	add(base64.URLEncoding.EncodeToString(b))
	add(base64.RawURLEncoding.EncodeToString(b))

	// base32
	add(base32.StdEncoding.EncodeToString(b))
	add(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))

	// hex (lower + upper)
	h := hex.EncodeToString(b)
	add(h)
	add(strings.ToUpper(h))

	// URL percent-encoding
	add(url.QueryEscape(v))
	add(url.PathEscape(v))

	// JSON string escaping (strip the surrounding quotes json.Marshal adds)
	if j, err := json.Marshal(v); err == nil {
		add(strings.Trim(string(j), `"`))
	}

	// raw bits (each byte as 8 bits)
	add(toBits(b))

	// Cheap reversible transforms an exfiltrator might use to dodge substring DLP
	// (e.g. `… | rev`, case-folding). Arbitrary transforms (gzip, ROT-n, base-N)
	// cannot be enumerated here and are covered by the network egress gateway.
	add(reverseBytes(b))
	if low := strings.ToLower(v); low != v {
		add(low)
	}
	if up := strings.ToUpper(v); up != v {
		add(up)
	}

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out
}

// reverseBytes returns b reversed (matches `rev` on ASCII secrets).
func reverseBytes(b []byte) string {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return string(r)
}

func toBits(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 8)
	for _, c := range b {
		fmt.Fprintf(&sb, "%08b", c)
	}
	return sb.String()
}

// allVariants returns the de-duplicated set of guarded encodings for all values.
func allVariants(values []string) []string {
	set := make(map[string]struct{}, len(values)*12)
	for _, v := range values {
		for _, variant := range variants(v) {
			set[variant] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out
}
