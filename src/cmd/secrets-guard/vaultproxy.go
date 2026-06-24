package main

import (
	"fmt"

	"github.com/hsoftai/hsoft-claude-plugins/internal/cache"
	"github.com/hsoftai/hsoft-claude-plugins/internal/catalog"
	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/hook"
	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// secrets-guard runs entirely LOCALLY: it reads vault metadata and values through the
// user's own `ksm` / `op` profile (in its default location). There is no sandbox-dlp
// service, no WinFsp, and nothing that needs administrator rights. The MCP tools and the
// proactive redaction guard both use the local vault plus the per-session in-memory cache.

// mcpCatalog returns the local vault catalog backing the MCP discovery tools.
func mcpCatalog(cfg config.Config) (catalog.Catalog, error) {
	return catalog.Select(cfg.VaultProvider, vault.NewRunner(), cfg.OPAccount)
}

// createSecret creates a secret in the local vault and returns its metadata + reference.
func createSecret(cfg config.Config, dest, title string, fields map[string]string) (catalog.Item, error) {
	return catalog.CreateSecret(vault.NewRunner(), cfg.OPAccount, dest, title, fields)
}

// allVaultValues returns every secret value the local vault exposes to the user's
// credential, for preloading the per-session in-memory cache (the proactive redaction
// guard) so any of them is redacted/blocked before it can reach the model.
func allVaultValues(cfg config.Config) ([]string, error) {
	r := vault.NewRunner()
	res, err := vault.Select(cfg.VaultProvider, r, cfg.OPAccount)
	if err != nil {
		return nil, err
	}
	if res.ProviderName() == "none" {
		return nil, fmt.Errorf("no vault available (install the ksm/op CLI and initialize a profile)")
	}
	return vault.AllSecretValues(r, res.ProviderName())
}

// valueGuard is the per-session in-memory value cache that backs the redaction guard.
func valueGuard() hook.SecretCache { return cache.New() }
