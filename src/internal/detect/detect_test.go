package detect

import (
	"strings"
	"testing"
)

// hasCategory reports whether findings contain at least one finding of cat.
func hasCategory(fs []Finding, cat Category) bool {
	for _, f := range fs {
		if f.Category == cat {
			return true
		}
	}
	return false
}

func TestScan_Positives(t *testing.T) {
	eng := New()

	cases := []struct {
		name string
		text string
		want Category
	}{
		{"aws access key id", "deploy with AKIAIOSFODNN7EXAMPLE now", CategoryAWSAccessKey},
		{"aws temp key", "token ASIAY34FZKBOKMUTVV7A here", CategoryAWSAccessKey},
		{"aws secret contextual", `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, CategoryAWSSecretKey},
		{"gcp api key", "key=AIza" + "SyA1234567890abcdefghijklmnopqrstuv", CategoryGCPAPIKey},
		{"gcp service account", `{"type":"service_account","private_key":"-----BEGIN ` + `PRIVATE KEY-----\nMIIE"}`, CategoryPrivateKey},
		{"azure storage key", "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + strings.Repeat("A", 86) + "==;EndpointSuffix=core.windows.net", CategoryAzureStorageKey},
		{"jwt", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", CategoryJWT},
		{"github pat classic", "GH_TOKEN=ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz", CategoryGitHubToken},
		{"github fine-grained", "token github_pat_" + "11ABCDEFG0aBcDeFgHiJkL_1234567890abcdefghijklmnopqrstuvwxyz1234567890ABCD", CategoryGitHubToken},
		{"slack token", "SLACK=xoxb-" + "2345678901-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx", CategorySlackToken},
		{"stripe live", "STRIPE_KEY=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dcABCDEF1234", CategoryStripeKey},
		{"anthropic", "ANTHROPIC_API_KEY=sk-ant-" + "api03-abcdefABCDEF1234567890_-xyz", CategoryAnthropicKey},
		{"ssh private key", "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----", CategoryPrivateKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := eng.Scan(tc.text)
			if !hasCategory(fs, tc.want) {
				t.Fatalf("expected category %s in %q, got %+v", tc.want, tc.text, fs)
			}
		})
	}
}

func TestScan_Negatives(t *testing.T) {
	eng := New()

	cases := []struct {
		name string
		text string
	}{
		{"plain sentence", "Please update the user password reset flow in the docs."},
		{"git sha", "commit 9f2a1c3e4b5d6a7f8e9d0c1b2a3f4e5d6c7b8a9f"},
		{"uuid", "id: 550e8400-e29b-41d4-a716-446655440000"},
		{"short base64", "data:aGVsbG8gd29ybGQ="},
		{"random word", "the quick brown fox jumps over the lazy dog"},
		{"keeper reference", "use keeper://AbC123/field/password for the db"},
		{"op reference", "use op://vault/item/password for the db"},
		{"version string", "running version 2.1.174 of the tool"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := eng.Scan(tc.text)
			if len(fs) != 0 {
				t.Fatalf("expected no findings in %q, got %+v", tc.text, fs)
			}
		})
	}
}

// Vault references must never be treated as secrets — they are the safe form.
func TestScan_IgnoresVaultReferences(t *testing.T) {
	eng := New()
	refs := []string{
		"keeper://3FXqmP5nFKwju0H8pl0DmQ/field/password",
		"op://Private/AWS/secret_access_key",
		"akv://my-vault/db-password",
	}
	for _, r := range refs {
		if fs := eng.Scan(r); len(fs) != 0 {
			t.Fatalf("vault reference %q must not be flagged, got %+v", r, fs)
		}
	}
}

func TestFinding_OffsetsMatchValue(t *testing.T) {
	eng := New()
	text := "key=AIza" + "SyA1234567890abcdefghijklmnopqrstuv end"
	fs := eng.Scan(text)
	if len(fs) == 0 {
		t.Fatal("expected a finding")
	}
	f := fs[0]
	if got := text[f.Start:f.End]; got != f.Value {
		t.Fatalf("offsets %d:%d give %q but Value is %q", f.Start, f.End, got, f.Value)
	}
}
