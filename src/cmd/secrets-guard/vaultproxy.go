package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/hsoftai/hsoft-claude-plugins/internal/cache"
	"github.com/hsoftai/hsoft-claude-plugins/internal/catalog"
	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/dlpipc"
	"github.com/hsoftai/hsoft-claude-plugins/internal/hook"
	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// serviceVaultCatalog implements catalog.Catalog by delegating to the sandbox-dlp service,
// which is the only holder of the vault credential. This lets the MCP list/search secrets
// (metadata + references, never values) without the client/agent ever reaching the vault.
type serviceVaultCatalog struct{}

func (serviceVaultCatalog) call(req projection.VaultRequest, out any) error {
	resp, err := dlpipc.Call(projection.ControlRequest{Op: projection.OpVault, Vault: &req})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	if out != nil && len(resp.Payload) > 0 {
		return json.Unmarshal(resp.Payload, out)
	}
	return nil
}

func (s serviceVaultCatalog) Provider() string {
	var r struct {
		Provider string `json:"provider"`
	}
	if err := s.call(projection.VaultRequest{Action: projection.VaultProvider}, &r); err != nil || r.Provider == "" {
		return "none"
	}
	return r.Provider
}

func (s serviceVaultCatalog) ListAccounts() ([]catalog.Account, error) {
	var a []catalog.Account
	return a, s.call(projection.VaultRequest{Action: projection.VaultAccounts}, &a)
}

func (s serviceVaultCatalog) ListVaults(account string) ([]catalog.Vault, error) {
	var v []catalog.Vault
	return v, s.call(projection.VaultRequest{Action: projection.VaultVaults, Account: account}, &v)
}

func (s serviceVaultCatalog) ListItems(account, vlt string) ([]catalog.Item, error) {
	var it []catalog.Item
	return it, s.call(projection.VaultRequest{Action: projection.VaultItems, Account: account, Vault: vlt}, &it)
}

func (s serviceVaultCatalog) ListFields(item, account, vlt string) ([]catalog.Field, error) {
	var f []catalog.Field
	return f, s.call(projection.VaultRequest{Action: projection.VaultFields, Item: item, Account: account, Vault: vlt}, &f)
}

// useServiceVault reports whether vault catalog operations should go through the service
// (Windows kernel-DLP, where the client holds no credential) rather than the local vault.
func useServiceVault(cfg config.Config) bool {
	return kernelDLPActive(cfg) && dlpipc.Healthy()
}

// mcpCatalog returns the catalog the MCP should use: the service proxy when the credential
// lives only in the service, otherwise the local vault.
func mcpCatalog(cfg config.Config) (catalog.Catalog, error) {
	if useServiceVault(cfg) {
		return serviceVaultCatalog{}, nil
	}
	return catalog.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount)
}

// createSecret creates a secret either through the service (credential-isolated path) or
// the local vault, returning the new item's metadata + reference (never a value).
func createSecret(cfg config.Config, dest, title string, fields map[string]string) (catalog.Item, error) {
	if useServiceVault(cfg) {
		var it catalog.Item
		err := (serviceVaultCatalog{}).call(projection.VaultRequest{
			Action: projection.VaultCreate, Vault: dest, Title: title, Fields: fields,
		}, &it)
		return it, err
	}
	return catalog.CreateSecret(vault.NewRunner(), cfg.OPAccount, dest, title, fields)
}

// allVaultValues returns every secret value the LOCAL vault exposes, for preloading the
// per-session in-memory cache (the proactive redaction guard) on macOS/Linux, where the
// client holds the credential. On Windows the client holds no credential and the cache
// is unavailable, so the guard runs in the service instead (serviceCache + OpScan).
func allVaultValues(cfg config.Config) ([]string, error) {
	r := vault.NewRunner()
	res, err := vault.Select(cfg.VaultProvider, r, cfg.OPAccount)
	if err != nil {
		return nil, err
	}
	if res.ProviderName() == "none" {
		return nil, fmt.Errorf("no vault available")
	}
	return vault.AllSecretValues(r, res.ProviderName())
}

// serviceCache implements hook.SecretCache by delegating redaction to the sandbox-dlp
// service (Windows), which holds every vault value in its own RAM and returns only the
// already-redacted text. This is the proactive guard on Windows, where the client has no
// credential and the per-user unix-socket cache does not apply. Add/Shutdown are no-ops:
// the service sources and scopes the values itself.
type serviceCache struct{}

func (serviceCache) Add(string, []string) {}

func (serviceCache) Scan(_, text string) (found bool, redacted string, ok bool) {
	resp, err := dlpipc.Call(projection.ControlRequest{
		Op:   projection.OpScan,
		Scan: &projection.ScanRequest{Text: text},
	})
	if err != nil || !resp.OK {
		return false, text, false // service unreachable: caller falls back
	}
	return resp.Found, resp.Redacted, true
}

func (serviceCache) Shutdown(string) {}

// requireServiceGuard reports whether the redaction guard MUST run in the sandbox-dlp
// service: on Windows (not Cowork) with the guard enabled, the service is the sole holder
// of the vault values and the per-user socket cache does not apply, so there is no local
// fallback. This is INDEPENDENT of KERNEL_DLP / sandbox — the guard is the always-on core
// even when reference rendering is off. When it returns true the hook is told to FAIL
// CLOSED if the service is unreachable (a crashed service must never silently leak).
func requireServiceGuard(cfg config.Config) bool {
	return runtime.GOOS == "windows" && !cfg.IsCowork && cfg.PreloadEnabled()
}

// valueGuard chooses where the resolved/known-value redaction guard lives: the service
// on Windows (it holds the values; the local socket cache does not apply there), the
// per-session in-memory cache otherwise. On the service path it best-effort (re)starts
// the service if it is down, so a transient crash self-heals.
func valueGuard(cfg config.Config) hook.SecretCache {
	if requireServiceGuard(cfg) {
		ensureServiceRunning()
		return serviceCache{}
	}
	return cache.New()
}

// ensureServiceRunning best-effort (re)starts the installed sandbox-dlp service when it is
// not answering, so a mid-session crash recovers without waiting for the next logon. No-op
// off Windows, when the service already answers, or when it is not installed (then the
// hook fails closed). Briefly waits so the current hook invocation can use the guard.
func ensureServiceRunning() {
	if runtime.GOOS != "windows" || dlpipc.Healthy() {
		return
	}
	exe := filepath.Join(os.Getenv("LOCALAPPDATA"), "secrets-guard", "sandbox-dlp", "sandbox-dlp.exe")
	if _, err := os.Stat(exe); err != nil {
		return // not installed — nothing to start
	}
	cmd := exec.Command(exe, "serve")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	cache.Detach(cmd)
	if err := cmd.Start(); err != nil {
		return
	}
	_ = cmd.Process.Release()
	for i := 0; i < 15; i++ { // ~1.5s for this call to use the guard; else next call retries
		if dlpipc.Healthy() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
