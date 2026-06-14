package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/hsoftai/hsoft-claude-plugins/internal/audit"
	"github.com/hsoftai/hsoft-claude-plugins/internal/broker"
	"github.com/hsoftai/hsoft-claude-plugins/internal/cache"
	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/seen"
	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// resolutionIsBroker reports whether reference resolution would go through the
// Cowork broker (i.e. this process is the VM-side client) rather than a local
// vault. Mirrors the selection in resolveRefs.
func resolutionIsBroker(cfg config.Config) bool {
	switch cfg.ExecutionMode {
	case "broker":
		return true
	case "local":
		return false
	default:
		r, _ := vault.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount)
		return r == nil || r.ProviderName() == "none"
	}
}

// resolveRefs resolves vault references to their values. On the host (and in
// plain Claude Code) it uses the local vault CLI; inside the Cowork VM — where no
// vault CLI exists — it fetches the values from the host broker over the
// authenticated TLS channel, using them only in memory. Selection honors
// execution_mode (auto|local|broker); in `auto` it uses the local vault when one
// is available and the broker otherwise. Returns ref->value.
func resolveRefs(cfg config.Config, refs []string) (map[string]string, error) {
	uniq := dedupe(refs)
	if len(uniq) == 0 {
		return map[string]string{}, nil
	}

	useBroker := false
	switch cfg.ExecutionMode {
	case "broker":
		useBroker = true
	case "local":
		useBroker = false
	default: // auto
		r, _ := vault.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount)
		useBroker = r == nil || r.ProviderName() == "none"
	}

	if useBroker {
		bs, spool, ok := broker.DiscoverBootstrap(os.Getenv("SG_SESSION"), broker.CandidateSpools(cfg.CoworkSpool))
		if !ok {
			return nil, fmt.Errorf("no hay bóveda local ni broker de Cowork disponible para resolver las referencias")
		}
		return broker.Client{Bootstrap: bs, Spool: spool, ExecID: os.Getenv("SG_EXEC_ID")}.Resolve(uniq)
	}

	resolver, err := vault.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(uniq))
	for _, ref := range uniq {
		v, vals, rerr := resolver.ResolveString(ref)
		if rerr != nil {
			return nil, rerr
		}
		if len(vals) > 0 {
			out[ref] = vals[0]
		} else {
			out[ref] = v
		}
	}
	return out, nil
}

// runBroker runs the host-side broker daemon for one Cowork session: it resolves
// vault references with the local vault and serves the values to the VM client
// over an authenticated, pinned TLS channel. It is started detached from the
// SessionStart hook. The secret values are written only to the socket; the spool
// only ever receives the control-plane bootstrap (token + address + cert pin).
func runBroker() {
	cfg := config.Load(os.Getenv)
	session := os.Getenv("SG_SESSION")
	if session == "" {
		fmt.Fprintln(os.Stderr, "secrets-guard broker: SG_SESSION requerido")
		os.Exit(2)
	}
	spool := coworkSpool(cfg)
	if spool == "" {
		fmt.Fprintln(os.Stderr, "secrets-guard broker: no hay spool de Cowork configurado (cowork_spool)")
		os.Exit(2)
	}
	resolver, err := vault.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard broker:", err)
		os.Exit(1)
	}

	tokenB64, terr := broker.NewToken()
	if terr != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard broker:", terr)
		os.Exit(1)
	}
	token := broker.Bootstrap{TokenB64: tokenB64}.Token()
	aud := audit.New(cfg.AuditLogPath)

	h := &broker.Handler{
		Token:    token,
		Resolver: resolver,
		Allowed:  func(ref string) bool { return seenHas(session, ref) },
		Enforce:  cfg.BrokerRefPolicy == "enforce",
		OnResolve: func(ref, value string) {
			// Register the value with the host session guard so PostToolUse can
			// detect/redact it if it later reappears in the VM's tool output.
			cache.New().Add(session, []string{value})
			seen.RecordPaths(session, []string{ref})
			aud.Log(audit.Record{SessionID: session, Event: "Broker", Action: "resolve", Count: 1})
		},
	}
	if err := broker.RunServer(broker.ServerConfig{
		Session:  session,
		Spool:    spool,
		VmnetIP:  cfg.BrokerHost, // "" => broker.DefaultVmnetIP (172.16.10.1)
		Port:     cfg.BrokerPort,
		TokenB64: tokenB64,
		Handler:  h,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard broker:", err)
		os.Exit(1)
	}
}

// shouldRunBroker reports whether this host should start a broker for the
// session: explicit broker mode, or auto mode on a host that has both a Cowork
// spool configured and a local vault (i.e. it can resolve and serve). Plain
// Claude Code (no spool) never starts a broker.
func shouldRunBroker(cfg config.Config) bool {
	if cfg.ExecutionMode == "local" {
		return false
	}
	if cfg.ExecutionMode == "broker" {
		return coworkSpool(cfg) != ""
	}
	if coworkSpool(cfg) == "" {
		return false
	}
	r, _ := vault.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount)
	return r != nil && r.ProviderName() != "none"
}

// spawnBroker starts the broker daemon detached, once per session (idempotent: it
// skips if a fresh bootstrap already exists).
func spawnBroker(cfg config.Config, session string) {
	if session == "" {
		return
	}
	if bs, err := broker.ReadBootstrap(coworkSpool(cfg), session); err == nil && !bs.Expired() {
		return
	}
	self, err := os.Executable()
	if err != nil {
		return
	}
	c := exec.Command(self, "broker")
	c.Env = append(os.Environ(), "SG_SESSION="+session)
	c.Stdin, c.Stdout, c.Stderr = nil, nil, nil
	cache.Detach(c)
	if err := c.Start(); err == nil {
		_ = c.Process.Release()
	}
}

// coworkSpool returns the host-side path of the shared `outputs` mount.
func coworkSpool(cfg config.Config) string { return cfg.CoworkSpool }

// cleanupBroker removes the session's control-plane files from the spool on
// SessionEnd (the host can delete; the VM cannot). The broker process also
// removes them on its own exit and rotates its token every start.
func cleanupBroker(cfg config.Config, session string) {
	sp := coworkSpool(cfg)
	if sp == "" || session == "" {
		return
	}
	broker.RemoveBootstrap(sp, session)
	broker.RemoveRendezvous(sp, session)
}

// seenHas reports whether ref is in the session's allowlist (the refs the host
// has observed in tool inputs this session, recorded in the seen ledger).
func seenHas(session, ref string) bool {
	for _, p := range seen.LoadPaths(session) {
		if p == ref {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	seenSet := make(map[string]struct{}, len(in))
	out := in[:0:0]
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
