// Package seen prevents a resolved secret from leaking when tools are chained
// (e.g. a value written to a file and later read back). It keeps, per Claude
// session, only the VAULT REFERENCES (op:// / keeper:// paths) that have been
// used — paths are not secret, so they may live on disk. The secret VALUES are
// never stored anywhere: when a tool result arrives, the caller re-resolves the
// accumulated paths from the vault into ephemeral memory and searches the text
// for those values by direct substring (no hashing — exact, catches embedded
// occurrences, and O(n·k) rather than O(n²)).
package seen

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// minLen is the shortest resolved value worth matching. Kept low (4) so short
// secrets (e.g. PINs) are still redacted/blocked rather than slipping into the
// transcript; 1–3 byte values are skipped to avoid pathological over-redaction.
const minLen = 4

// Placeholder replaces a recognized resolved value in redacted output.
const Placeholder = "[REDACTED BY SECRETS-GUARD]"

// dir returns a PRIVATE per-user state directory for the reference ledger — NOT a
// bare, shared, world-known path in /tmp. Bare /tmp (sticky 1777) plus a fixed
// directory name let any local user pre-create `secrets-guard-paths` owned by
// themselves (mode 0700): the victim's MkdirAll then no-ops on the existing dir
// and every RecordPaths write fails (no write permission in the attacker-owned
// dir), so the ledger stays empty and the resolved-value leak backstop (the
// PreToolUse known-value DENY and the PostToolUse leak-block, which fall back to
// re-resolving these paths when the in-memory cache is down) is silently disabled.
// Keying the directory by uid keeps other users out; verifyOwned re-checks it is
// our own 0700 dir on every use so a pre-planted dir is rejected, not adopted.
func dir() string {
	// SG_PATHS_DIR pins the ledger directory explicitly. The sandbox sets this when
	// it re-execs under `unshare --map-root-user` (where os.Getuid() is the mapped 0,
	// not the host uid) so the ledger it writes lands in the SAME per-host-uid
	// directory the host hooks read — otherwise the rendered-value leak backstop is
	// silently keyed to a uid-0 path the host never consults.
	if d := os.Getenv("SG_PATHS_DIR"); d != "" {
		_ = os.MkdirAll(d, 0o700)
		return d
	}
	d := filepath.Join(os.TempDir(), fmt.Sprintf("secrets-guard-paths-%d", os.Getuid()))
	_ = os.MkdirAll(d, 0o700)
	return d
}

// VerifyOwned reports whether dir is a directory we own exclusively (mode 0700, no
// group/other access). It is the shared ownership guard used by every per-user state
// directory in secrets-guard (the reference ledger here, and the cache socket dir in
// internal/cache) so a co-resident user cannot pre-plant a directory and intercept
// the backstop. Exported so other packages can reuse the exact same check.
func VerifyOwned(dir string) bool { return verifyOwned(dir) }

// verifyOwned reports whether dir is a directory we own with no access for group
// or other (mode 0700). A pre-planted, attacker-owned, or loosely-permissioned dir
// fails this check, so the caller refuses to read/write the ledger through it.
func verifyOwned(dir string) bool {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	if !permOK(fi) {
		return false // (Unix) group/other have access — not exclusively ours
	}
	return ownedByUs(fi) // platform check: refuse a dir owned by another user
}

// Path returns the per-session reference ledger file (sanitized session id).
func Path(session string) string {
	s := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '_'
	}, session)
	if s == "" {
		s = "default"
	}
	d := dir()
	if !verifyOwned(d) {
		return "" // dir is missing/hijacked/loose-permissioned — refuse to use it
	}
	return filepath.Join(d, s+".paths")
}

// RecordPaths appends vault references (not secret) to the session ledger,
// de-duplicated.
func RecordPaths(session string, refs []string) {
	if len(refs) == 0 {
		return
	}
	path := Path(session)
	if path == "" {
		return // ledger dir is not safely owned by us — fail closed, do not write
	}
	existing := map[string]struct{}{}
	for _, p := range LoadPaths(session) {
		existing[p] = struct{}{}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	for _, r := range refs {
		if r == "" {
			continue
		}
		if _, ok := existing[r]; ok {
			continue
		}
		existing[r] = struct{}{}
		_, _ = f.WriteString(r + "\n")
	}
}

// LoadPaths returns the references recorded for a session.
func LoadPaths(session string) []string { return loadPath(Path(session)) }

func loadPath(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// Clear removes a session's reference ledger.
func Clear(session string) { _ = os.Remove(Path(session)) }

// Contains reports whether text contains any resolved value, in any guarded
// encoding (raw, base64, base32, hex, URL, JSON, bits).
func Contains(text string, values []string) bool {
	for _, v := range allVariants(values) {
		if strings.Contains(text, v) {
			return true
		}
	}
	return false
}

// Redact replaces every occurrence of a resolved value — in any guarded encoding
// — with Placeholder. Longer needles are replaced first so an encoding that
// contains another is handled cleanly.
func Redact(text string, values []string) (string, int) {
	needles := allVariants(values)
	sort.Slice(needles, func(i, j int) bool { return len(needles[i]) > len(needles[j]) })
	n := 0
	for _, v := range needles {
		if c := strings.Count(text, v); c > 0 {
			text = strings.ReplaceAll(text, v, Placeholder)
			n += c
		}
	}
	return text, n
}
