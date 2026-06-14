package detect

import "testing"

func TestAddPattern_CustomCategory(t *testing.T) {
	eng := New()
	if err := eng.AddPattern("NIT", `\bNIT-\d{9}\b`); err != nil {
		t.Fatal(err)
	}
	fs := eng.Scan("factura del cliente NIT-900123456 emitida")
	if !hasCategory(fs, "NIT") {
		t.Fatalf("custom NIT pattern not detected: %+v", fs)
	}
}

func TestAddPattern_InvalidRegex(t *testing.T) {
	eng := New()
	if err := eng.AddPattern("BAD", `([`); err == nil {
		t.Fatal("expected error on invalid regex")
	}
}

func TestAllowlist_SuppressesFinding(t *testing.T) {
	eng := New()
	// Sanity: flagged by default.
	if fs := eng.Scan("AKIAIOSFODNN7EXAMPLE"); len(fs) == 0 {
		t.Fatal("precondition: example key should be flagged")
	}
	if err := eng.AddAllowlistPattern(`AKIAIOSFODNN7EXAMPLE`); err != nil {
		t.Fatal(err)
	}
	if fs := eng.Scan("AKIAIOSFODNN7EXAMPLE"); len(fs) != 0 {
		t.Fatalf("allowlisted value should be suppressed, got %+v", fs)
	}
}
