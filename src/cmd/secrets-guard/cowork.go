package main

// Cowork secure-channel wiring. In Claude Cowork the agent's Bash runs in an
// isolated VM with no vault CLI and no network path to the host; the ONLY channel
// is the shared `outputs` disk mount. Secrets are delivered over that disk safely
// with an asymmetric sealed box (internal/cowork):
//
//   - cw-host (HOST daemon): owns the per-session Ed25519 identity, resolves
//     references with the local vault, and answers VM requests — sealing each value
//     to the VM's ephemeral public key and signing the envelope.
//   - cw-run  (VM): receives the trust anchor (host public key) on its command line
//     and the one-time token on a file descriptor (never argv/env/disk), fetches the
//     values into memory, injects them into the child's environment, and execs.
//
// The hook mints, per command, an exec id + one-time token + the host public key,
// persisting {exec id -> token, allowed refs} in a HOST-ONLY directory the daemon
// reads (the VM never sees it). That binds each fetch to refs the host approved.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hsoftai/hsoft-claude-plugins/internal/audit"
	"github.com/hsoftai/hsoft-claude-plugins/internal/cache"
	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/cowork"
	"github.com/hsoftai/hsoft-claude-plugins/internal/seen"
	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// coworkAnchor implements hook.CoworkAnchor on the host: it mints the per-command
// exec id, host public key and one-time token (persisted in the host-only dir).
type coworkAnchor struct{}

func (coworkAnchor) Mint(session string, allowed []string) (execID, hostPubB64, tokenB64 string, ok bool) {
	return mintExec(session, allowed)
}

// execTTL bounds how long a minted exec token is valid (a generous window that
// still covers a Touch-ID prompt). After it the daemon ignores the exec.
const execTTL = 30 * time.Minute

// coworkFetchTimeout is how long cw-run waits for the host to answer.
const coworkFetchTimeout = 90 * time.Second

// coworkIdle is how long the host daemon stays up without delivering a value.
const coworkIdle = 30 * time.Minute

// execRecord is the host-only record binding an exec id to its one-time token and
// the references the host authorized for it (least privilege per command).
type execRecord struct {
	TokenB64 string   `json:"token"`
	Refs     []string `json:"refs"`
	Stamp    int64    `json:"stamp"`
}

// coworkHostDir returns (creating it) the HOST-ONLY state directory for a session.
// It lives under the user config dir — NOT under the shared `outputs` spool — so
// the VM can never read the tokens or the host private key.
func coworkHostDir(session string) (string, error) {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", herr
		}
		base = filepath.Join(home, ".config")
	}
	dir := filepath.Join(base, "secrets-guard", "cowork", safeName(session))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// loadOrCreateHostIdentity returns the session's host signing identity and its
// public key (base64). Creation is atomic (O_EXCL) so the hook and the daemon
// converge on the SAME identity regardless of who runs first.
func loadOrCreateHostIdentity(session string) (*cowork.HostSigner, string, error) {
	dir, err := coworkHostDir(session)
	if err != nil {
		return nil, "", err
	}
	seedPath := filepath.Join(dir, "host.seed")
	if signer, pub, ok := readIdentity(seedPath); ok {
		return signer, pub, nil
	}
	signer, _, err := cowork.NewHost()
	if err != nil {
		return nil, "", err
	}
	seedB64 := base64.StdEncoding.EncodeToString(signer.Seed())
	f, ferr := os.OpenFile(seedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if ferr != nil {
		// Someone created it first — read theirs so we agree on one identity.
		if signer2, pub2, ok := readIdentity(seedPath); ok {
			return signer2, pub2, nil
		}
		return nil, "", ferr
	}
	_, werr := f.WriteString(seedB64)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		return nil, "", fmt.Errorf("writing host identity: %v / %v", werr, cerr)
	}
	return signer, base64.StdEncoding.EncodeToString(signer.Public()), nil
}

func readIdentity(seedPath string) (*cowork.HostSigner, string, bool) {
	data, err := os.ReadFile(seedPath)
	if err != nil {
		return nil, "", false
	}
	seed, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if derr != nil {
		return nil, "", false
	}
	signer, pub, err := cowork.NewHostFromSeed(seed)
	if err != nil {
		return nil, "", false
	}
	return signer, base64.StdEncoding.EncodeToString(pub), true
}

// mintExec creates a one-time anchor for a command that will run in the VM: an
// exec id, the host public key (base64, the command-line trust anchor) and a
// single-use token (handed to the VM over a file descriptor). It persists
// {exec id -> token, allowed refs} in the host-only dir for the daemon. Implements
// hook.CoworkAnchor.
func mintExec(session string, allowed []string) (execID, hostPubB64, tokenB64 string, ok bool) {
	if session == "" {
		return "", "", "", false
	}
	_, pub, err := loadOrCreateHostIdentity(session)
	if err != nil {
		return "", "", "", false
	}
	dir, err := coworkHostDir(session)
	if err != nil {
		return "", "", "", false
	}
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return "", "", "", false
	}
	execID = cowork.NewExecID()
	tokenB64 = base64.StdEncoding.EncodeToString(tok)
	rec := execRecord{TokenB64: tokenB64, Refs: dedupe(allowed), Stamp: time.Now().Unix()}
	data, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(dir, "exec-"+safeName(execID)+".json"), data, 0o600); err != nil {
		return "", "", "", false
	}
	return execID, pub, tokenB64, true
}

// lookupExec is the daemon's Auth callback: it returns the token and approved refs
// for an exec id (or ok=false if unknown/expired). Single-use is enforced by
// retireExec after delivery.
func lookupExec(session, execID string) (token []byte, allowed []string, ok bool) {
	dir, err := coworkHostDir(session)
	if err != nil {
		return nil, nil, false
	}
	data, err := os.ReadFile(filepath.Join(dir, "exec-"+safeName(execID)+".json"))
	if err != nil {
		return nil, nil, false
	}
	var rec execRecord
	if json.Unmarshal(data, &rec) != nil {
		return nil, nil, false
	}
	if rec.Stamp > 0 && time.Since(time.Unix(rec.Stamp, 0)) > execTTL {
		return nil, nil, false
	}
	tok, derr := base64.StdEncoding.DecodeString(rec.TokenB64)
	if derr != nil || len(tok) == 0 {
		return nil, nil, false
	}
	return tok, rec.Refs, true
}

// retireExec removes a served exec record so its token is strictly single-use.
func retireExec(session, execID string) {
	if dir, err := coworkHostDir(session); err == nil {
		_ = os.Remove(filepath.Join(dir, "exec-"+safeName(execID)+".json"))
	}
}

// runCwHost is the HOST daemon: it answers VM requests over the spool for one
// Cowork session. Started detached from the SessionStart hook.
func runCwHost() {
	cfg := config.Load(os.Getenv)
	session := os.Getenv("SG_SESSION")
	if session == "" {
		fmt.Fprintln(os.Stderr, "secrets-guard cw-host: SG_SESSION requerido")
		os.Exit(2)
	}
	spool := cfg.CoworkSpool
	if spool == "" {
		fmt.Fprintln(os.Stderr, "secrets-guard cw-host: sin spool de Cowork (CLAUDE_PROJECT_DIR/cowork_spool)")
		os.Exit(2)
	}
	signer, _, err := loadOrCreateHostIdentity(session)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard cw-host:", err)
		os.Exit(1)
	}
	resolver, err := vault.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard cw-host:", err)
		os.Exit(1)
	}
	aud := audit.New(cfg.AuditLogPath)

	// Single-instance guard: refresh a host-only lock; a fresh lock means a daemon
	// is already serving this session, so exit.
	if !claimDaemonLock(session) {
		return
	}

	opts := cowork.HostOpts{
		Resolver: resolver,
		Signer:   signer,
		Enforce:  cfg.CoworkRefPolicy == "enforce",
		Auth: func(execID string) ([]byte, []string, bool) {
			return lookupExec(session, execID)
		},
		OnResolve: func(ref, value string) {
			// Register on the host so PostToolUse can detect/redact the value if it
			// later reappears in the VM's tool output.
			cache.New().Add(session, []string{value})
			seen.RecordPaths(session, []string{ref})
			aud.Log(audit.Record{SessionID: session, Event: "Cowork", Action: "resolve", Count: 1})
		},
		OnServed: func(execID string) { retireExec(session, execID) },
	}

	stop := make(chan struct{})
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		<-ch
		close(stop)
	}()
	_ = cowork.Watch(spool, opts, coworkIdle, stop)
}

// claimDaemonLock atomically claims a host-only single-instance lock; returns false
// if another daemon already holds a fresh lock (so this one should exit). The claim
// is an O_EXCL create (no check-then-write TOCTOU); a stale lock (older than the
// idle window, e.g. a crashed daemon) is reclaimed once.
func claimDaemonLock(session string) bool {
	dir, err := coworkHostDir(session)
	if err != nil {
		return true // best-effort: if we cannot lock, still run
	}
	lock := filepath.Join(dir, "daemon.lock")
	try := func() bool {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
			_ = f.Close()
			return true
		}
		return false
	}
	if try() {
		return true
	}
	// Lock exists: only reclaim if it is stale.
	if fi, serr := os.Stat(lock); serr == nil && time.Since(fi.ModTime()) >= coworkIdle {
		_ = os.Remove(lock)
		return try()
	}
	return false
}

// spawnCwHost starts the host daemon detached, once per session (idempotent via
// the daemon lock).
func spawnCwHost(cfg config.Config, session string) {
	if session == "" || cfg.CoworkSpool == "" {
		return
	}
	if dir, err := coworkHostDir(session); err == nil {
		lock := filepath.Join(dir, "daemon.lock")
		if fi, err := os.Stat(lock); err == nil && time.Since(fi.ModTime()) < coworkIdle {
			return // a daemon is already serving this session
		}
	}
	self, err := os.Executable()
	if err != nil {
		return
	}
	c := exec.Command(self, "cw-host")
	c.Env = append(os.Environ(), "SG_SESSION="+session)
	c.Stdin, c.Stdout, c.Stderr = nil, nil, nil
	cache.Detach(c)
	if err := c.Start(); err == nil {
		_ = c.Process.Release()
	}
}

// cwRunOpts holds the parsed cw-run command line.
type cwRunOpts struct {
	hostPubB64 string
	execID     string
	authFD     int
	isolate    bool
	spoolHint  string
	envFiles   []string
	cmd        []string
}

func parseCwRun(args []string) (cwRunOpts, error) {
	o := cwRunOpts{authFD: -1}
	// The anchor fields are normally provided via the environment (authoritative).
	// We still parse them from argv for direct/manual invocation, but FIRST-WINS:
	// once set, a later duplicate flag is ignored. Combined with the env override in
	// applyEnvAnchor, an injected duplicate anchor flag cannot take effect.
	var gotHostPub, gotExecID, gotAuthFD, gotSpool bool
	i := 0
	for i < len(args) {
		a := args[i]
		next := func() (string, bool) {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		switch {
		case a == "--":
			i++
			o.cmd = args[i:]
			return o, nil
		case a == "--context" || strings.HasPrefix(a, "--context="):
			if a == "--context" {
				i++
			}
			i++
		case a == "--host-pub":
			v, ok := next()
			if !ok {
				return o, fmt.Errorf("--host-pub requiere valor")
			}
			if !gotHostPub {
				o.hostPubB64, gotHostPub = v, true
			}
			i += 2
		case a == "--exec-id":
			v, ok := next()
			if !ok {
				return o, fmt.Errorf("--exec-id requiere valor")
			}
			if !gotExecID {
				o.execID, gotExecID = v, true
			}
			i += 2
		case a == "--auth-fd":
			v, ok := next()
			if !ok {
				return o, fmt.Errorf("--auth-fd requiere valor")
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return o, fmt.Errorf("--auth-fd inválido: %v", err)
			}
			if !gotAuthFD {
				o.authFD, gotAuthFD = n, true
			}
			i += 2
		case a == "--spool-hint":
			v, ok := next()
			if !ok {
				return o, fmt.Errorf("--spool-hint requiere valor")
			}
			if !gotSpool {
				o.spoolHint, gotSpool = v, true
			}
			i += 2
		case a == "--env-file":
			v, ok := next()
			if !ok {
				return o, fmt.Errorf("--env-file requiere valor")
			}
			o.envFiles = append(o.envFiles, v)
			i += 2
		case a == "--isolate":
			o.isolate = true
			i++
		default:
			// First non-flag token begins the command (tolerate a missing `--`).
			o.cmd = args[i:]
			return o, nil
		}
	}
	return o, nil
}

// applyEnvAnchor overrides the anchor fields from the environment, which the hook
// sets in the command prefix. The environment is authoritative over argv so the
// agent-controlled arguments appended after `cw-run` can never substitute a
// different trust anchor, auth fd, exec id, or spool.
func applyEnvAnchor(o *cwRunOpts) {
	hostPub := strings.TrimSpace(os.Getenv("SG_CW_HOSTPUB"))
	if hostPub != "" {
		o.hostPubB64 = hostPub
	}
	if v := strings.TrimSpace(os.Getenv("SG_CW_EXECID")); v != "" {
		o.execID = v
	}
	if v := strings.TrimSpace(os.Getenv("SG_CW_AUTHFD")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			o.authFD = n
		}
	}
	if hostPub != "" {
		// Hook-driven path: the spool is discovered, never taken from the
		// agent-controlled args. An attacker-provided --spool-hint would only cause
		// a timeout (responses must be signed by the real host key), but we remove
		// even that by forcing discovery here. An explicit SG_CW_SPOOL still wins.
		o.spoolHint = strings.TrimSpace(os.Getenv("SG_CW_SPOOL"))
	} else if v := strings.TrimSpace(os.Getenv("SG_CW_SPOOL")); v != "" {
		o.spoolHint = v
	}
	if os.Getenv("SG_CW_ISOLATE") == "1" {
		o.isolate = true
	}
}

// runCwRun is the VM-side fetch+exec. It reads the one-time token from a file
// descriptor (never argv/env), fetches the approved references' values into memory
// over the sealed-box disk channel, injects them into the child's environment, and
// execs the child. Values never touch the VM's shell, disk, or argv.
func runCwRun() {
	o, err := parseCwRun(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard cw-run:", err)
		os.Exit(2)
	}
	// The anchor comes from the ENVIRONMENT (set by the hook in the command prefix),
	// which is authoritative: agent-controlled argv can never override it. This is
	// what prevents a `--host-pub <attacker>` / `--auth-fd 0` injection through the
	// args appended after `cw-run`.
	applyEnvAnchor(&o)
	if len(o.cmd) == 0 {
		fmt.Fprintln(os.Stderr, "usage: secrets-guard cw-run --host-pub B64 --exec-id ID --auth-fd N [--env-file F]... -- CMD...")
		os.Exit(2)
	}

	// Optional defense-in-depth: re-exec under a user/pid/mount namespace so other
	// VM processes (same uid) cannot inspect this process's /proc. Probe support
	// once per VM; fall back to running un-isolated (isolation is not the
	// confidentiality boundary — the never-transmitted private key is).
	if o.isolate && os.Getenv("SG_IN_NS") != "1" && unshareSupported() {
		reexecUnderNamespace(o)
		return
	}

	if o.authFD < 0 {
		fmt.Fprintln(os.Stderr, "secrets-guard cw-run: falta --auth-fd")
		os.Exit(2)
	}
	tokenFile := os.NewFile(uintptr(o.authFD), "sg-auth")
	if tokenFile == nil {
		fmt.Fprintln(os.Stderr, "secrets-guard cw-run: descriptor de token inválido")
		os.Exit(2)
	}
	tokRaw, _ := io.ReadAll(io.LimitReader(tokenFile, 4096))
	tokenFile.Close()
	token, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(tokRaw)))
	if derr != nil || len(token) == 0 {
		fmt.Fprintln(os.Stderr, "secrets-guard cw-run: token ausente o inválido")
		os.Exit(2)
	}
	pubBytes, perr := base64.StdEncoding.DecodeString(strings.TrimSpace(o.hostPubB64))
	if perr != nil || len(pubBytes) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "secrets-guard cw-run: --host-pub inválido (ancla de confianza)")
		os.Exit(2)
	}
	hostPub := ed25519.PublicKey(pubBytes)

	spool, serr := cowork.DiscoverSpool(o.spoolHint)
	if serr != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard cw-run:", serr)
		os.Exit(1)
	}

	// Build the child environment and collect every reference across env values and
	// the named env-files (the references are paths, not secrets).
	env := environMap()
	for _, f := range o.envFiles {
		if err := loadEnvFile(f, env); err != nil {
			fmt.Fprintln(os.Stderr, "secrets-guard cw-run:", err)
			os.Exit(1)
		}
	}
	var allRefs []string
	refsByKey := map[string][]string{}
	for k, v := range env {
		if r := vault.FindReferences(v); len(r) > 0 {
			refsByKey[k] = r
			allRefs = append(allRefs, r...)
		}
	}

	if len(allRefs) > 0 {
		values, ferr := cowork.Fetch(spool, o.execID, allRefs, hostPub, token, coworkFetchTimeout)
		if ferr != nil {
			fmt.Fprintln(os.Stderr, "secrets-guard cw-run:", ferr)
			os.Exit(1)
		}
		for k, refs := range refsByKey {
			s := env[k]
			for _, ref := range refs {
				val, ok := values[ref]
				if !ok {
					fmt.Fprintf(os.Stderr, "secrets-guard cw-run: no se pudo resolver %s\n", ref)
					os.Exit(1)
				}
				s = strings.ReplaceAll(s, ref, val)
			}
			env[k] = s
		}
	}

	// Do not leak our control variables into the user's program environment.
	for k := range env {
		if strings.HasPrefix(k, "SG_CW_") || k == "SG_IN_NS" {
			delete(env, k)
		}
	}

	c := exec.Command(o.cmd[0], o.cmd[1:]...)
	c.Env = mapToEnv(env)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "secrets-guard cw-run:", err)
		os.Exit(1)
	}
}

// reexecUnderNamespace re-runs cw-run wrapped in `unshare`, passing the token file
// descriptor through to the child (as fd 3) so the secret stays off argv/env. The
// child sees SG_IN_NS=1 and proceeds without re-isolating.
func reexecUnderNamespace(o cwRunOpts) {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard cw-run:", err)
		os.Exit(1)
	}
	nsFlags := []string{"--user", "--map-root-user", "--pid", "--mount", "--fork", "--mount-proc"}
	// The child reads the anchor from the ENVIRONMENT (inherited), never argv, and
	// the token at fd 3 (ExtraFiles[0]). We only forward the non-anchor args
	// (env-files + the command).
	childArgs := []string{"cw-run"}
	for _, f := range o.envFiles {
		childArgs = append(childArgs, "--env-file", f)
	}
	childArgs = append(childArgs, "--")
	childArgs = append(childArgs, o.cmd...)

	full := append([]string{self}, childArgs...)
	c := exec.Command("unshare", append(nsFlags, full...)...)
	// Anchor via env (already present from the parent's env); pin the child's auth
	// fd to 3 and mark it as already-namespaced so it does not re-isolate.
	c.Env = append(os.Environ(), "SG_IN_NS=1", "SG_CW_AUTHFD=3", "SG_CW_SPOOL="+o.spoolHint)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if o.authFD >= 0 {
		if tf := os.NewFile(uintptr(o.authFD), "sg-auth"); tf != nil {
			c.ExtraFiles = []*os.File{tf} // becomes fd 3 in the child
		}
	}
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "secrets-guard cw-run (ns):", err)
		os.Exit(1)
	}
}

// unshareSupported probes whether unprivileged user namespaces work in this VM. We
// do NOT cache the result on disk: a cache file in a shared tmp dir would let a
// co-resident process (same uid) plant a "no" to force the non-isolated fallback.
// The probe is a single fast exec; isolation is defense-in-depth, not the
// confidentiality boundary, so the extra probe cost is acceptable.
func unshareSupported() bool {
	c := exec.Command("unshare", "--user", "--map-root-user", "--pid", "--mount", "--fork", "--mount-proc", "true")
	return c.Run() == nil
}

// safeName sanitizes a session/exec id for use as a filesystem path component.
func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}
