// Package catalog lists the metadata of a vault — accounts, item titles and
// field labels with their reference paths — WITHOUT ever returning secret
// values. It backs the MCP tools that let Claude discover which secret to use
// and build the correct keeper:// / op:// reference, which the PreToolUse hook
// then resolves at execution. Claude sees references and labels, never values.
//
// For 1Password, references are emitted with the account embedded
// (op://<account>:vault/item/field) so a single session can mix secrets from
// several accounts without any global configuration.
package catalog

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// Account is a vault account (no credentials).
type Account struct {
	ID    string `json:"id"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

// Vault is a container of items within an account.
type Vault struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Items int    `json:"items,omitempty"`
}

// Item is a vault entry (no secret material).
type Item struct {
	Title   string `json:"title"`
	ID      string `json:"id"`
	Vault   string `json:"vault,omitempty"`
	Type    string `json:"type,omitempty"`
	Account string `json:"account,omitempty"`
}

// Field is one field of an item: its label/type and the reference to use. The
// value is deliberately absent.
type Field struct {
	Label     string `json:"label"`
	Type      string `json:"type,omitempty"`
	Reference string `json:"reference"`
}

// Catalog lists accounts, vaults, items and fields for one vault provider. An
// empty account/vault argument means "no filter / default".
type Catalog interface {
	Provider() string
	ListAccounts() ([]Account, error)
	ListVaults(account string) ([]Vault, error)
	ListItems(account, vault string) ([]Item, error)
	ListFields(item, account, vault string) ([]Field, error)
}

// Select returns the catalog for the active provider (first-found-wins, Keeper
// preferred), mirroring vault.Select.
func Select(pref string, r vault.Runner, opAccount string) (Catalog, error) {
	kAvail := r.Look("ksm")
	oAvail := r.Look("op")

	pick := pref
	if pick == "auto" || pick == "" {
		switch {
		case kAvail:
			pick = "keeper"
		case oAvail:
			pick = "1password"
		default:
			return nil, fmt.Errorf("no hay una bóveda disponible (instala/configura Keeper o 1Password)")
		}
	}

	switch pick {
	case "keeper":
		if !kAvail {
			return nil, fmt.Errorf("Keeper (ksm) no está instalado")
		}
		return &keeperCat{r: r}, nil
	case "1password":
		if !oAvail {
			return nil, fmt.Errorf("1Password (op) no está instalado")
		}
		return &opCat{r: r, account: opAccount}, nil
	default:
		return nil, fmt.Errorf("proveedor de bóveda desconocido: %q", pick)
	}
}

// --- 1Password ---

type opCat struct {
	r       vault.Runner
	account string
}

func (o *opCat) Provider() string { return "1password" }

func (o *opCat) effective(account string) string {
	if account != "" {
		return account
	}
	return o.account
}

func (o *opCat) args(account string, a ...string) []string {
	if eff := o.effective(account); eff != "" {
		a = append(a, "--account", eff)
	}
	return a
}

// flagLike reports whether an untrusted catalog argument (account/vault/item)
// could be parsed as an `op` flag. Such names are rejected so a VM-supplied value
// can never be smuggled as an option (parity with the resolver's hardening).
func flagLike(s string) bool { return strings.HasPrefix(s, "-") }

func (o *opCat) ListAccounts() ([]Account, error) {
	out, err := o.r.Run("op", "account", "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		AccountUUID string `json:"account_uuid"`
		URL         string `json:"url"`
		Email       string `json:"email"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("op account list: %w", err)
	}
	accts := make([]Account, 0, len(raw))
	for _, a := range raw {
		accts = append(accts, Account{ID: a.AccountUUID, URL: a.URL, Email: a.Email})
	}
	return accts, nil
}

func (o *opCat) ListVaults(account string) ([]Vault, error) {
	out, err := o.r.Run("op", o.args(account, "vault", "list", "--format", "json")...)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("op vault list: %w", err)
	}
	vaults := make([]Vault, 0, len(raw))
	for _, v := range raw {
		vaults = append(vaults, Vault{ID: v.ID, Name: v.Name})
	}
	return vaults, nil
}

func (o *opCat) ListItems(account, vault string) ([]Item, error) {
	if flagLike(account) || flagLike(vault) {
		return nil, fmt.Errorf("invalid account/vault name")
	}
	cmd := []string{"item", "list", "--format", "json"}
	if vault != "" {
		cmd = append(cmd, "--vault", vault)
	}
	out, err := o.r.Run("op", o.args(account, cmd...)...)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID    string `json:"id"`
		Title string `json:"title"`
		Vault struct {
			Name string `json:"name"`
		} `json:"vault"`
		Category string `json:"category"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("op item list: %w", err)
	}
	eff := o.effective(account)
	items := make([]Item, 0, len(raw))
	for _, r := range raw {
		items = append(items, Item{Title: r.Title, ID: r.ID, Vault: r.Vault.Name, Type: r.Category, Account: eff})
	}
	return items, nil
}

func (o *opCat) ListFields(item, account, vault string) ([]Field, error) {
	if flagLike(item) || flagLike(account) || flagLike(vault) {
		return nil, fmt.Errorf("invalid item/account/vault name")
	}
	cmd := []string{"item", "get", "--format", "json"}
	if vault != "" {
		cmd = append(cmd, "--vault", vault)
	}
	// Append --account (via args) and ONLY THEN the option terminator + positional
	// item, so `--` is the last flag and the item can never be read as an option.
	full := append(o.args(account, cmd...), "--", item)
	out, err := o.r.Run("op", full...)
	if err != nil {
		return nil, err
	}
	// NOTE: the JSON also carries each field's "value"; we deliberately do NOT
	// unmarshal it, so a value can never leak through this path.
	var raw struct {
		Fields []struct {
			Label     string `json:"label"`
			Type      string `json:"type"`
			Reference string `json:"reference"`
		} `json:"fields"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("op item get: %w", err)
	}
	eff := o.effective(account)
	fields := make([]Field, 0, len(raw.Fields))
	for _, f := range raw.Fields {
		if f.Reference == "" || f.Label == "" {
			continue
		}
		fields = append(fields, Field{Label: f.Label, Type: f.Type, Reference: withAccount(f.Reference, eff)})
	}
	return fields, nil
}

// withAccount embeds the account into an op:// reference so it is self-contained:
// op://vault/item/field -> op://<account>:vault/item/field.
func withAccount(ref, account string) string {
	const p = "op://"
	if account == "" || !strings.HasPrefix(ref, p) {
		return ref
	}
	return p + account + ":" + ref[len(p):]
}

// --- Keeper ---

type keeperCat struct {
	r vault.Runner
}

func (k *keeperCat) Provider() string { return "keeper" }

// Keeper has a single application context, so there is one logical account.
func (k *keeperCat) ListAccounts() ([]Account, error) {
	return []Account{{ID: "keeper"}}, nil
}

// Keeper (via KSM) exposes only the records shared to the application, not vaults.
func (k *keeperCat) ListVaults(_ string) ([]Vault, error) { return nil, nil }

func (k *keeperCat) ListItems(_, _ string) ([]Item, error) {
	out, err := k.r.Run("ksm", "secret", "list", "--json")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		UID        string `json:"uid"`
		Title      string `json:"title"`
		RecordType string `json:"record_type"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("ksm secret list: %w", err)
	}
	items := make([]Item, 0, len(raw))
	for _, r := range raw {
		items = append(items, Item{Title: r.Title, ID: r.UID, Type: r.RecordType})
	}
	return items, nil
}

func (k *keeperCat) ListFields(item, _, _ string) ([]Field, error) {
	// The item UID is attacker-influenced (the model passes it through the
	// list_fields MCP tool). Reject a flag-looking value so it can never be
	// smuggled as a `ksm` option via argument injection — parity with the
	// 1Password path's flagLike guard and the resolver's hardening.
	if flagLike(item) {
		return nil, fmt.Errorf("invalid item id")
	}
	out, err := k.r.Run("ksm", "secret", "get", "--uid", item, "--json")
	if err != nil {
		return nil, err
	}
	var raw struct {
		Fields []struct {
			Type  string `json:"type"`
			Label string `json:"label"`
		} `json:"fields"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("ksm secret get: %w", err)
	}
	fields := make([]Field, 0, len(raw.Fields))
	for _, f := range raw.Fields {
		if f.Type == "" {
			continue
		}
		label := f.Label
		if label == "" {
			label = f.Type
		}
		fields = append(fields, Field{
			Label:     label,
			Type:      f.Type,
			Reference: fmt.Sprintf("keeper://%s/field/%s", item, f.Type),
		})
	}
	return fields, nil
}
