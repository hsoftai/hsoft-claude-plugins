package detect

import "testing"

// Zero-false-positives guarantee: detection is a best-effort plus and must never
// flag normal source code, filenames, prose, config or vault references. We
// accept false negatives (the natural-language "la contraseña X" is NOT caught)
// in exchange for never blocking a developer. If any of these starts matching,
// it is a regression in the wrong direction.
func TestScan_NoFalsePositives(t *testing.T) {
	eng := New()
	mustBeClean := []string{
		// The exact case that wrongly blocked a write of a valid op:// reference.
		"op://Private/test-claude/password",
		"password-ref.txt",
		`Write file password-ref.txt with op://Private/test-claude/password`,
		// Vault references of every supported scheme.
		"keeper://3FXqmP5nFKwju0H8pl0DmQ/field/password",
		"op://development/GitHub/credentials/personal_token?attribute=otp",
		"akv://my-vault/db-password",
		// Natural-language credentials — intentionally NOT detected (no block).
		"la contraseña es Pr0dPass2026!",
		"the password is Adm1n#Str0ng2026",
		"usa estas credenciales para entrar: Str0ngP4ss!",
		"db_password: hunter2longvalue",
		"password=Sup3rSecret123",
		"set DB_PASSWORD to your value",
		// Credential-shaped URLs (placeholders / examples) — not flagged.
		"postgres://user:password@localhost:5432/app",
		"mongodb://admin:changeme@db.internal",
		// Ordinary source code and identifiers.
		"const awsSecretKey = getEnv('AWS_SECRET')",
		"refactor the password hashing in AuthModule2024",
		"rotate the api_key handling in TokenService2025",
		"call resetPassword(userId) then audit",
		"the secret config lives in /etc/app/config.yaml",
		"export TOKEN_TTL=3600 in the deployment",
		"a sha: 9f2a1c3e4b5d6a7f8e9d0c1b2a3f4e5d6c7b8a9f",
		"uuid 550e8400-e29b-41d4-a716-446655440000",
		"version 2.1.174 of the tool",
		"base64 payload aGVsbG8gd29ybGQ=",
	}
	for _, s := range mustBeClean {
		if fs := eng.Scan(s); len(fs) != 0 {
			t.Errorf("FALSE POSITIVE: %q flagged as %+v", s, fs)
		}
	}
}

// The high-confidence detectors still fire on real, unambiguous secrets.
func TestScan_StillCatchesHighConfidence(t *testing.T) {
	eng := New()
	mustDetect := []string{
		"deploy with AKIAIOSFODNN7EXAMPLE now",
		"GH_TOKEN=ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz",
		"ANTHROPIC_API_KEY=sk-ant-" + "api03-abcdefABCDEF1234567890_-xyz",
		"-----BEGIN OPENSSH " + "PRIVATE KEY-----",
	}
	for _, s := range mustDetect {
		if fs := eng.Scan(s); len(fs) == 0 {
			t.Errorf("expected a finding in %q", s)
		}
	}
}
