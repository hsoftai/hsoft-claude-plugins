package catalog

import (
	"strings"
	"testing"
)

// mockRunner returns canned CLI output keyed by full command line.
type mockRunner struct {
	present map[string]bool
	outputs map[string]string
}

func (m *mockRunner) Look(name string) bool { return m.present[name] }
func (m *mockRunner) Run(name string, args ...string) (string, error) {
	key := name + " " + strings.Join(args, " ")
	if out, ok := m.outputs[key]; ok {
		return out, nil
	}
	return "", &noOutErr{key}
}

type noOutErr struct{ key string }

func (e *noOutErr) Error() string { return "no canned output for: " + e.key }

func TestOnePassword_ListAccountsAndItems(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"op": true},
		outputs: map[string]string{
			"op account list --format json": `[
              {"account_uuid":"7FWKE","url":"my.1password.com","email":"a@porter.com"},
              {"account_uuid":"SELOG","url":"my.1password.com","email":"a@avantive.co"}]`,
			"op item list --format json --account 7FWKE": `[
              {"id":"abc","title":"test-claude","vault":{"name":"Private"},"category":"LOGIN"}]`,
		},
	}
	c, _ := Select("1password", m, "")

	accts, err := c.ListAccounts()
	if err != nil || len(accts) != 2 || accts[0].ID != "7FWKE" {
		t.Fatalf("accounts: %+v err=%v", accts, err)
	}

	items, err := c.ListItems("7FWKE", "") // per-call account
	if err != nil || len(items) != 1 || items[0].Title != "test-claude" || items[0].Account != "7FWKE" {
		t.Fatalf("items: %+v err=%v", items, err)
	}
}

func TestOnePassword_ListFields_PrefixesAccount_NoValues(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"op": true},
		outputs: map[string]string{
			"op item get test-claude --format json --account 7FWKE": `{"fields":[
                {"id":"username","type":"STRING","label":"username","value":"alice","reference":"op://Private/test-claude/username"},
                {"id":"password","type":"CONCEALED","label":"password","value":"S3cr3tV4lue!","reference":"op://Private/test-claude/password"},
                {"id":"sec","type":"STRING","label":"","value":"x","reference":""}]}`,
		},
	}
	c, _ := Select("1password", m, "")
	fields, err := c.ListFields("test-claude", "7FWKE", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d: %+v", len(fields), fields)
	}
	var pw *Field
	for i := range fields {
		if fields[i].Label == "password" {
			pw = &fields[i]
		}
	}
	// Reference must embed the account so it is self-contained for multi-account.
	if pw == nil || pw.Reference != "op://7FWKE:Private/test-claude/password" {
		t.Fatalf("password reference not account-prefixed: %+v", fields)
	}
	for _, f := range fields {
		if strings.Contains(f.Reference, "S3cr3tV4lue") || strings.Contains(f.Reference, "alice") {
			t.Fatalf("VALUE LEAKED: %+v", f)
		}
	}
}

func TestKeeper_ListItemsAndFields(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"ksm": true},
		outputs: map[string]string{
			"ksm secret list --json": `[{"uid":"3FXqmP5","title":"Prod DB","record_type":"databaseCredentials"}]`,
			"ksm secret get --uid 3FXqmP5 --json": `{"fields":[
                {"type":"login","label":"User"},
                {"type":"password","label":"Password"}]}`,
		},
	}
	c, _ := Select("keeper", m, "")
	items, err := c.ListItems("", "")
	if err != nil || len(items) != 1 || items[0].ID != "3FXqmP5" {
		t.Fatalf("items: %+v err=%v", items, err)
	}
	fields, err := c.ListFields("3FXqmP5", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var hasPw bool
	for _, f := range fields {
		if f.Reference == "keeper://3FXqmP5/field/password" {
			hasPw = true
		}
	}
	if !hasPw {
		t.Fatalf("expected keeper password reference, got %+v", fields)
	}
}

func TestOnePassword_ListVaultsAndVaultFilter(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"op": true},
		outputs: map[string]string{
			"op vault list --format json --account ACC":                `[{"id":"v1","name":"Private"},{"id":"v2","name":"Employee"}]`,
			"op item list --format json --vault Private --account ACC": `[{"id":"a","title":"db","vault":{"name":"Private"},"category":"LOGIN"}]`,
		},
	}
	c, _ := Select("1password", m, "ACC")

	vaults, err := c.ListVaults("")
	if err != nil || len(vaults) != 2 || vaults[1].Name != "Employee" {
		t.Fatalf("vaults: %+v err=%v", vaults, err)
	}

	// vault filter must add --vault so a huge shared vault can be narrowed at source
	items, err := c.ListItems("", "Private")
	if err != nil || len(items) != 1 || items[0].Title != "db" {
		t.Fatalf("vault-filtered items: %+v err=%v", items, err)
	}
}

func TestSelect_NoVault(t *testing.T) {
	m := &mockRunner{present: map[string]bool{}}
	if _, err := Select("auto", m, ""); err == nil {
		t.Fatal("expected error when no vault is installed")
	}
}
