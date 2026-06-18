package main

import (
	"encoding/json"
	"fmt"

	"github.com/hsoftai/hsoft-claude-plugins/internal/catalog"
	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/dlpipc"
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
