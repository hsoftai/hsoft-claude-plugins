package main

// `secrets-guard sandbox -- CMD…` renders vault references into their real values —
// in the command's ENVIRONMENT and inside matched FILES under the working directory
// — scoped to that one command via an ephemeral Linux mount namespace, then execs
// the command. The real disk is untouched; the namespace (and every value in its
// in-memory tmpfs) is torn down by the kernel when the command exits.
//
// Flow:
//   - Fast path: if no references are found in env or files, exec the command
//     directly (no namespace, no resolution).
//   - Env-only: if only env vars carry references (or file rendering is unavailable
//     — macOS/Windows, or namespaces disabled), resolve and render the environment.
//   - Full sandbox (Linux): re-exec under `unshare --user --map-root-user --mount`,
//     then (inside the namespace) resolve, render the environment, bind-mount each
//     rendered file over its original, and exec the command.
//
// Values are resolved locally (host with a vault) or fetched over the sealed-box
// disk channel (Cowork VM, anchor + one-time token delivered by the host hook in
// the command environment / on fd 3).

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/hsoftai/hsoft-claude-plugins/internal/cache"
	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/cowork"
	"github.com/hsoftai/hsoft-claude-plugins/internal/detect"
	"github.com/hsoftai/hsoft-claude-plugins/internal/redact"
	"github.com/hsoftai/hsoft-claude-plugins/internal/seen"
)

// Markers used to coordinate the re-exec and prevent nested re-rendering.
const (
	envInNamespace   = "SG_IN_NS"          // set when already inside the unshare namespace
	envSandboxActive = "SG_SANDBOX_ACTIVE" // set on the rendered child so nested calls no-op
)

// escapedRefRe matches a vault reference with an OPTIONAL leading backslash. The
// backslash opts that occurrence out of rendering: `\op://…` is kept LITERAL as
// `op://…` (the backslash stripped), exactly like the inline `command_references`
// escape. Group 1 is the escape, group 2 the reference.
var escapedRefRe = regexp.MustCompile(`(\\?)((?i:keeper|op|akv)://[A-Za-z0-9._\-/\[\]?=&:@]+)`)

// renderRefs replaces each (unescaped) reference with its value, strips the escape
// from `\op://…` (leaving the literal reference), and leaves unresolved references
// untouched. Used for env values, the command body, and file content alike.
func renderRefs(s string, values map[string]string) string {
	return escapedRefRe.ReplaceAllStringFunc(s, func(match string) string {
		sub := escapedRefRe.FindStringSubmatch(match)
		escaped, ref := sub[1] == `\`, sub[2]
		if escaped {
			return ref // strip backslash, keep literal — never resolve
		}
		if val, ok := values[ref]; ok {
			return val
		}
		return ref
	})
}

// unescapedRefs returns the references in s that are NOT backslash-escaped — the set
// the sandbox actually needs to resolve (an escaped occurrence is never fetched).
func unescapedRefs(s string) []string {
	var out []string
	for _, m := range escapedRefRe.FindAllStringSubmatch(s, -1) {
		if m[1] != `\` {
			out = append(out, m[2])
		}
	}
	return out
}

// runSandbox is the entrypoint for `secrets-guard sandbox`.
func runSandbox() {
	cmd := parseSandboxArgs(os.Args[2:])
	if len(cmd) == 0 {
		fmt.Fprintln(os.Stderr, "usage: secrets-guard sandbox [--] CMD [ARGS...]")
		os.Exit(2)
	}

	// Re-entrancy: an outer sandbox already rendered this environment/tree.
	if os.Getenv(envSandboxActive) == "1" {
		execCommandEnv(os.Environ(), cmd)
		return
	}

	cfg := config.Load(os.Getenv)

	// Already inside the namespace (re-exec): do the full render here.
	if os.Getenv(envInNamespace) == "1" {
		renderAndExec(cfg, cmd, true)
		return
	}

	// Outer process: detect whether ANY reference (escaped or not) is present, to
	// decide between the fast path and rendering. Escaped-only inputs still render
	// (to strip the backslash).
	anyCmdRef := false
	for _, a := range cmd {
		if escapedRefRe.MatchString(a) {
			anyCmdRef = true
			break
		}
	}
	var fileRefs []refFile
	canFiles := cfg.Sandbox != "off"
	if canFiles {
		fileRefs, _ = scanRefFiles(cwd(), parseGlobs(cfg.SandboxGlobs))
	}

	if !envHasAnyRef() && !anyCmdRef && len(fileRefs) == 0 {
		// Nothing to render — fast path.
		execCommandEnv(os.Environ(), cmd)
		return
	}

	// LINUX: render files via a private bind-mount inside a mount namespace, so the
	// value never touches the real disk. Only this path uses unshare.
	if runtime.GOOS == "linux" && canFiles && (len(fileRefs) > 0 || cfg.CoworkIsolate) && unshareSupported() {
		reexecSandboxNS(cfg, cmd)
		return
	}

	// Everywhere else (macOS/Windows, or Linux without namespaces): render env +
	// command always, and files IN PLACE with restore (no namespace). On Linux
	// without unshare we skip file rendering to avoid mutating real files unguarded.
	withFiles := canFiles && len(fileRefs) > 0 && runtime.GOOS != "linux"
	renderAndExec(cfg, cmd, withFiles)
}

// renderAndExec resolves every reference found in the environment (and, when
// withFiles, in matched files), renders the environment, optionally bind-mounts the
// rendered files, registers the values for output redaction, and execs the command.
func renderAndExec(cfg config.Config, cmd []string, withFiles bool) {
	env := environMap()

	// Collect the (unescaped) references to resolve, from THREE surfaces: env values,
	// the command body itself, and (on Linux) matched files under cwd.
	refSet := map[string]struct{}{}
	add := func(rs []string) {
		for _, r := range rs {
			refSet[r] = struct{}{}
		}
	}
	for _, v := range env {
		add(unescapedRefs(v))
	}
	// Command-body references are rendered unless command_references=keep (then they
	// are left literal, like the inline path).
	renderCmd := cfg.CommandReferences != "keep"
	if renderCmd {
		for _, a := range cmd {
			add(unescapedRefs(a))
		}
	}
	var files []refFile
	if withFiles {
		files, _ = scanRefFiles(cwd(), parseGlobs(cfg.SandboxGlobs))
		for _, f := range files {
			add(f.refs)
		}
	}

	refs := make([]string, 0, len(refSet))
	for r := range refSet {
		refs = append(refs, r)
	}

	// Resolve the unescaped references (if any). The render pass runs regardless, so
	// that an escaped occurrence (\op://…) still has its backslash stripped — matching
	// the inline `command_references` escape — even when nothing needs fetching.
	var values map[string]string
	if len(refs) > 0 {
		var err error
		values, err = sandboxResolve(cfg, refs)
		if err != nil {
			fmt.Fprintln(os.Stderr, "secrets-guard sandbox:", err)
			os.Exit(1)
		}
	}

	// 1) Render the ENVIRONMENT and 3) the COMMAND body (escape-aware: \op://… is
	// kept literal). The values live only in this process's memory + the child's
	// argv/env, never in the hook's returned command (the transcript keeps the
	// literal reference).
	for k := range env {
		env[k] = renderRefs(env[k], values)
	}
	if renderCmd {
		for i := range cmd {
			cmd[i] = renderRefs(cmd[i], values)
		}
	}

	// 2) Render FILES in place: Linux uses a private bind-mount (the value never touches
	// the real disk); macOS/Windows render the value onto the real file for the command's
	// duration and restore the original reference right after, backed by a crash-recovery
	// journal so a hard kill never leaves a value on disk.
	restore := func() {}
	childDir := ""
	if withFiles && len(files) > 0 {
		restore = inPlaceRender(files, values)
	}

	// Register resolved values so a rendered value printed in the output is caught by
	// the host PostToolUse leak-block (backstop). In Cowork the host daemon records
	// them too; this covers local mode.
	if session := os.Getenv("SG_SESSION"); session != "" {
		cache.New().Add(session, valueList(values))
		seen.RecordPaths(session, refs)
	}

	childEnv := mapToEnv(stripSandboxEnv(env))
	childEnv = append(childEnv, envSandboxActive+"=1")
	// Run the command (with its cwd inside the DLP mount when active), redact its output
	// inline (so a printed value is masked, not just blocked), and restore/deregister
	// afterward — even on a terminating signal.
	execChildWithRestore(childEnv, cmd, values, restore, childDir)
}

// inPlaceRender renders the ref-files in place (Linux bind-mount or macOS/Windows
// write+restore) and returns the restore function. On failure it warns and returns a
// no-op, leaving the files literal (env and command are still rendered).
func inPlaceRender(files []refFile, values map[string]string) func() {
	r, err := renderFiles(files, values)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard sandbox: file rendering unavailable:", err)
		return func() {}
	}
	if r == nil {
		return func() {}
	}
	return r
}

// valueList returns the resolved secret values as a slice (for redaction/registration).
func valueList(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	return out
}

// sandboxResolve resolves references either over the Cowork sealed-box channel (when
// the host hook supplied an anchor in the environment) or with the local vault.
func sandboxResolve(cfg config.Config, refs []string) (map[string]string, error) {
	if values, ok, err := coworkFetchFromEnv(refs); ok {
		return values, err
	}
	return resolveRefsLocal(cfg, refs)
}

// coworkFetchFromEnv fetches values over the sealed-box channel using the anchor the
// host hook placed in the environment (SG_CW_HOSTPUB/EXECID/AUTHFD/SPOOL) and the
// one-time token on the auth fd. ok is false when no anchor is present (local mode).
func coworkFetchFromEnv(refs []string) (map[string]string, bool, error) {
	hostPubB64 := strings.TrimSpace(os.Getenv("SG_CW_HOSTPUB"))
	if hostPubB64 == "" {
		return nil, false, nil
	}
	pubBytes, err := base64.StdEncoding.DecodeString(hostPubB64)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, true, fmt.Errorf("invalid SG_CW_HOSTPUB (trust anchor)")
	}
	execID := strings.TrimSpace(os.Getenv("SG_CW_EXECID"))
	authFD, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("SG_CW_AUTHFD")))
	if authFD <= 0 {
		return nil, true, fmt.Errorf("missing SG_CW_AUTHFD")
	}
	tf := os.NewFile(uintptr(authFD), "sg-auth")
	if tf == nil {
		return nil, true, fmt.Errorf("invalid auth fd")
	}
	tokRaw, _ := io.ReadAll(io.LimitReader(tf, 4096))
	tf.Close()
	token, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(tokRaw)))
	if derr != nil || len(token) == 0 {
		return nil, true, fmt.Errorf("missing/invalid one-time token")
	}
	spool, serr := cowork.DiscoverSpool(strings.TrimSpace(os.Getenv("SG_CW_SPOOL")))
	if serr != nil {
		return nil, true, serr
	}
	vals, ferr := cowork.Fetch(spool, execID, refs, ed25519.PublicKey(pubBytes), token, coworkFetchTimeout)
	return vals, true, ferr
}

// reexecSandboxNS re-execs `secrets-guard sandbox` inside an unprivileged user+mount
// namespace, passing the token fd through to fd 3 and the anchor via the environment.
// The child (SG_IN_NS=1) performs discovery, resolution and rendering inside the ns.
func reexecSandboxNS(cfg config.Config, cmd []string) {
	self, err := os.Executable()
	if err != nil {
		renderAndExec(cfg, cmd, false) // fall back to env-only
		return
	}
	nsFlags := []string{"--user", "--map-root-user", "--mount", "--fork"}
	if cfg.CoworkIsolate {
		nsFlags = append(nsFlags, "--pid", "--mount-proc")
	}
	args := append([]string{self, "sandbox", "--"}, cmd...)

	c := exec.Command("unshare", append(nsFlags, args...)...)
	c.Env = append(os.Environ(), envInNamespace+"=1", "SG_CW_AUTHFD=3")
	// Pin the leak-backstop directories to the HOST uid's paths. Inside the
	// `unshare --map-root-user` namespace os.Getuid() is the mapped 0, so without
	// this the child would register rendered values under /tmp/secrets-guard-*-0
	// while the host PostToolUse hook scans /tmp/secrets-guard-*-<realuid> — the
	// value would be fetched and rendered but never registered for the leak-block,
	// so a command that prints it would reach the model. Compute the paths here, in
	// the outer (pre-unshare) process, where the uid is still the real host uid.
	c.Env = append(c.Env,
		"SG_CACHE_DIR="+hostCacheDir(),
		"SG_PATHS_DIR="+hostPathsDir(),
	)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Pass the one-time token fd through as fd 3 in the child (never argv/env).
	if fdStr := strings.TrimSpace(os.Getenv("SG_CW_AUTHFD")); fdStr != "" {
		if n, e := strconv.Atoi(fdStr); e == nil && n > 0 {
			if tf := os.NewFile(uintptr(n), "sg-auth"); tf != nil {
				c.ExtraFiles = []*os.File{tf}
			}
		}
	}
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		// unshare itself failed (namespace unsupported at runtime) → env-only fallback.
		renderAndExec(cfg, cmd, false)
	}
	os.Exit(0)
}

// --- helpers ---

// hostCacheDir / hostPathsDir compute the per-host-uid leak-backstop directories
// from the OUTER process (before unshare), so the namespace child — where Getuid()
// is the mapped 0 — registers rendered values where the host hooks will find them.
// Any pre-set override (operator config, or the Cowork host) is honored as-is.
func hostCacheDir() string {
	if d := os.Getenv("SG_CACHE_DIR"); d != "" {
		return d
	}
	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = os.TempDir()
	}
	return fmt.Sprintf("%s/secrets-guard-sock-%d", base, os.Getuid())
}

func hostPathsDir() string {
	if d := os.Getenv("SG_PATHS_DIR"); d != "" {
		return d
	}
	return fmt.Sprintf("%s/secrets-guard-paths-%d", os.TempDir(), os.Getuid())
}

// parseSandboxArgs returns the command after an optional leading `--`.
func parseSandboxArgs(args []string) []string {
	if len(args) > 0 && args[0] == "--" {
		return args[1:]
	}
	return args
}

// envHasAnyRef reports whether any environment value contains a reference (escaped
// or not) — the cheap gate for whether the environment needs a render pass.
func envHasAnyRef() bool {
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 && escapedRefRe.MatchString(kv[i+1:]) {
			return true
		}
	}
	return false
}

// envReferenceSet returns the unique UNESCAPED references present across env values.
func envReferenceSet() []string {
	set := map[string]struct{}{}
	for _, kv := range os.Environ() {
		i := strings.IndexByte(kv, '=')
		if i < 0 {
			continue
		}
		for _, r := range unescapedRefs(kv[i+1:]) {
			set[r] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	return out
}

// stripSandboxEnv removes secrets-guard control variables from a child environment.
func stripSandboxEnv(env map[string]string) map[string]string {
	for k := range env {
		if strings.HasPrefix(k, "SG_CW_") || k == envInNamespace || k == envSandboxActive ||
			k == "SG_PATHS_DIR" || k == "SG_CACHE_DIR" {
			delete(env, k)
		}
	}
	return env
}

func cwd() string {
	if d, err := os.Getwd(); err == nil {
		return d
	}
	return "."
}

// execCommandEnv runs cmd with the given environment, propagating its exit code, and
// exits. Used for the fast path (no secrets) — no redaction, no restore.
func execCommandEnv(env, cmd []string) {
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Env = env
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "secrets-guard sandbox:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// execChildWithRestore runs the rendered command with its output redacted inline,
// then restores any in-place-rendered files — exactly once, even if the process is
// interrupted by a terminating signal mid-command. (On Linux, restore is a no-op:
// the namespace's bind-mounts vanish on exit.)
func execChildWithRestore(env, cmd []string, values map[string]string, restore func(), dir string) {
	var once sync.Once
	doRestore := func() {
		if restore != nil {
			once.Do(restore)
		}
	}
	if restore != nil {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-ch
			doRestore()
			os.Exit(130)
		}()
	}
	code := runChildRedacted(env, cmd, values, dir)
	doRestore()
	os.Exit(code)
}

// runChildRedacted runs the command and streams its stdout/stderr through redaction:
// every resolved value (in any guarded encoding) and any high-confidence detected
// secret is masked before it reaches the caller. Returns the child's exit code.
func runChildRedacted(env, cmd []string, values map[string]string, dir string) int {
	vlist := valueList(values)
	eng := detect.New()
	red := redact.New(eng)
	redactLine := func(s string) string {
		if len(vlist) > 0 {
			s, _ = seen.Redact(s, vlist)
		}
		out, _ := red.Redact(s)
		return out
	}

	c := exec.Command(cmd[0], cmd[1:]...)
	c.Env = env
	c.Stdin = os.Stdin
	c.Dir = dir // empty = inherit cwd; set to the DLP mountpoint when kernel DLP is active
	outR, oerr := c.StdoutPipe()
	errR, eerr := c.StderrPipe()
	if oerr != nil || eerr != nil {
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		return runAndCode(c)
	}
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard sandbox:", err)
		return 1
	}
	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(r io.Reader, w io.Writer) {
		defer wg.Done()
		br := bufio.NewReader(r)
		for {
			line, err := br.ReadString('\n')
			if len(line) > 0 {
				fmt.Fprint(w, redactLine(line))
			}
			if err != nil {
				return
			}
		}
	}
	go pump(outR, os.Stdout)
	go pump(errR, os.Stderr)
	wg.Wait()
	return runAndCode2(c.Wait())
}

func runAndCode(c *exec.Cmd) int { return runAndCode2(c.Run()) }

func runAndCode2(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 1
}
