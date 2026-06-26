package vault

import (
	"strings"
	"testing"
)

func contains(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

func TestAllSecretValues_Keeper(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"ksm": true},
		outputs: map[string]string{
			"ksm secret list --json": `[{"uid":"UID1"},{"uid":"UID2"}]`,
			// The preload passes --unmask so password-like fields return real values.
			"ksm secret get --uid UID1 --json --unmask": `{"uid":"UID1","title":"prod-db","type":"login",
				"fields":[{"type":"login","value":["dbadmin"]},{"type":"password","value":["S3cretPassw0rd"]}],
				"custom":[{"type":"text","label":"token","value":["tok_abcdef123456"]},{"type":"pin","value":["123"]}],
				"notes":"a memorable note"}`,
			// UID2 repeats a value (dedup) and adds a fresh one.
			"ksm secret get --uid UID2 --json --unmask": `{"uid":"UID2","title":"x",
				"fields":[{"type":"password","value":["S3cretPassw0rd"]},{"type":"password","value":["AnotherPass99"]}]}`,
		},
	}

	vals, err := AllSecretValues(m, "keeper")
	if err != nil {
		t.Fatal(err)
	}

	// Secret field/custom values and notes are collected (password, custom token, notes).
	for _, want := range []string{"S3cretPassw0rd", "tok_abcdef123456", "AnotherPass99", "a memorable note"} {
		if !contains(vals, want) {
			t.Errorf("expected value %q to be collected, got %v", want, vals)
		}
	}
	// The username (login field) is LEFT VISIBLE — only secrets are redacted. Metadata
	// (title, uid, field type/label) is never collected either.
	for _, no := range []string{"dbadmin", "prod-db", "UID1", "UID2", "login", "password", "token"} {
		if contains(vals, no) {
			t.Errorf("metadata %q must not be collected as a value, got %v", no, vals)
		}
	}
	// Values shorter than bulkMinLen are dropped (avoids pathological over-redaction).
	if contains(vals, "123") {
		t.Errorf("short value %q must be dropped, got %v", "123", vals)
	}
	// De-duplicated across records.
	n := 0
	for _, v := range vals {
		if v == "S3cretPassw0rd" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected the repeated value once after dedup, got %d", n)
	}
	// The get call MUST request --unmask; otherwise ksm returns masked password fields
	// ("******") and a login record's real password would never enter the redaction guard.
	if !contains(m.calls, "ksm secret get --uid UID1 --json --unmask") {
		t.Errorf("preload must call `ksm secret get ... --unmask`, calls were %v", m.calls)
	}
}

func TestAllSecretValues_OnePassword(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"op": true},
		outputs: map[string]string{
			"op item list --format json":          `[{"id":"abc123"}]`,
			"op item get --format json -- abc123": `{"id":"abc123","title":"api","fields":[{"id":"password","purpose":"PASSWORD","value":"hunter2hunter"},{"id":"username","purpose":"USERNAME","value":"svc-acct"}]}`,
		},
	}
	vals, err := AllSecretValues(m, "1password")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(vals, "hunter2hunter") {
		t.Errorf("password must be collected, got %v", vals)
	}
	// The username (purpose USERNAME) is left visible — not loaded into the guard.
	if contains(vals, "svc-acct") {
		t.Errorf("username must NOT be collected (left visible), got %v", vals)
	}
}

func TestAllSecretValues_UnknownProvider(t *testing.T) {
	if _, err := AllSecretValues(&mockRunner{}, "azure"); err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("expected unknown-provider error, got %v", err)
	}
}

func TestAllSecretValues_ListErrorPropagates(t *testing.T) {
	// No canned output for the list call -> the mock returns an error, which must surface.
	if _, err := AllSecretValues(&mockRunner{present: map[string]bool{"ksm": true}}, "keeper"); err == nil {
		t.Fatal("expected an error when the vault list call fails")
	}
}
