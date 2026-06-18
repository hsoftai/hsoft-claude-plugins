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
			"ksm secret get --uid UID1 --json": `{"uid":"UID1","title":"prod-db","type":"login",
				"fields":[{"type":"login","value":["dbadmin"]},{"type":"password","value":["S3cretPassw0rd"]}],
				"custom":[{"type":"text","label":"token","value":["tok_abcdef123456"]},{"type":"pin","value":["123"]}],
				"notes":"a memorable note"}`,
			// UID2 repeats a value (dedup) and adds a fresh one.
			"ksm secret get --uid UID2 --json": `{"uid":"UID2","title":"x",
				"fields":[{"type":"password","value":["S3cretPassw0rd"]},{"type":"password","value":["AnotherPass99"]}]}`,
		},
	}

	vals, err := AllSecretValues(m, "keeper")
	if err != nil {
		t.Fatal(err)
	}

	// Every field/custom value and the notes are collected.
	for _, want := range []string{"dbadmin", "S3cretPassw0rd", "tok_abcdef123456", "AnotherPass99", "a memorable note"} {
		if !contains(vals, want) {
			t.Errorf("expected value %q to be collected, got %v", want, vals)
		}
	}
	// Metadata (title, uid, field type/label) is NEVER collected.
	for _, no := range []string{"prod-db", "UID1", "UID2", "login", "password", "token"} {
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
}

func TestAllSecretValues_OnePassword(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"op": true},
		outputs: map[string]string{
			"op item list --format json":              `[{"id":"abc123"}]`,
			"op item get --format json -- abc123":     `{"id":"abc123","title":"api","fields":[{"label":"password","value":"hunter2hunter"},{"label":"username","value":"svc-acct"}]}`,
		},
	}
	vals, err := AllSecretValues(m, "1password")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"hunter2hunter", "svc-acct"} {
		if !contains(vals, want) {
			t.Errorf("expected %q, got %v", want, vals)
		}
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
