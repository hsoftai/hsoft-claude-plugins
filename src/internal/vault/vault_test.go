package vault

import (
	"strings"
	"testing"
)

// mockRunner stands in for exec of ksm / op.
type mockRunner struct {
	present map[string]bool
	outputs map[string]string // key: name + " " + strings.Join(args, " ")
	calls   []string
}

func (m *mockRunner) Look(name string) bool { return m.present[name] }

func (m *mockRunner) Run(name string, args ...string) (string, error) {
	key := name + " " + strings.Join(args, " ")
	m.calls = append(m.calls, key)
	if out, ok := m.outputs[key]; ok {
		return out, nil
	}
	return "", &runErr{key}
}

type runErr struct{ key string }

func (e *runErr) Error() string { return "no canned output for: " + e.key }

func TestKeeper_Resolve(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"ksm": true},
		outputs: map[string]string{
			"ksm secret notation keeper://UID1/field/password": "S3CRET-VALUE\n",
		},
	}
	p := newKeeper(m)
	got, err := p.Resolve("keeper://UID1/field/password", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "S3CRET-VALUE" {
		t.Fatalf("got %q, want trimmed S3CRET-VALUE", got)
	}
}

func TestOnePassword_Resolve(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"op": true},
		outputs: map[string]string{
			"op read -- op://Private/AWS/password": "hunter2\n",
		},
	}
	p := newOnePassword(m, "")
	got, err := p.Resolve("op://Private/AWS/password", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Fatalf("got %q", got)
	}
}

func TestResolver_ResolveString_ReplacesRef(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"ksm": true},
		outputs: map[string]string{
			"ksm secret notation keeper://UID1/field/password": "PLAINPASS\n",
		},
	}
	r, err := Select("keeper", m, "")
	if err != nil {
		t.Fatal(err)
	}
	out, _vals, err := r.ResolveString("export DB=keeper://UID1/field/password && run")
	n := len(_vals)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 resolution, got %d", n)
	}
	if !strings.Contains(out, "PLAINPASS") || strings.Contains(out, "keeper://") {
		t.Fatalf("ref not replaced: %q", out)
	}
}

// With multiple 1Password accounts, secrets-guard must pass --account so op
// does not fail with "multiple accounts found".
func TestOnePassword_ResolveWithAccount(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"op": true},
		outputs: map[string]string{
			"op read --account my.1password.com -- op://Private/test-claude/password": "TOPsecret\n",
		},
	}
	r, _ := Select("1password", m, "my.1password.com")
	out, _vals, err := r.ResolveString("write op://Private/test-claude/password please")
	n := len(_vals)
	if err != nil || n != 1 || !strings.Contains(out, "TOPsecret") {
		t.Fatalf("account ref: out=%q n=%d err=%v (calls=%v)", out, n, err, m.calls)
	}
}

// Account embedded in the reference: op://<account>:vault/item/field. This lets
// a single session use secrets from several accounts at once.
func TestResolveString_AccountInReference(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"op": true},
		outputs: map[string]string{
			"op read --account 7FWKE -- op://Private/test-claude/password": "REALVAL\n",
		},
	}
	r, _ := Select("1password", m, "") // no global account configured
	out, _vals, err := r.ResolveString("write op://7FWKE:Private/test-claude/password please")
	n := len(_vals)
	if err != nil || n != 1 || !strings.Contains(out, "REALVAL") || strings.Contains(out, "7FWKE") {
		t.Fatalf("account-in-ref: out=%q n=%d err=%v (calls=%v)", out, n, err, m.calls)
	}
}

// An email account works too (contains @, no ':').
func TestResolveString_EmailAccountInReference(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"op": true},
		outputs: map[string]string{
			"op read --account alexis@portermetrics.com -- op://Private/x/y": "V\n",
		},
	}
	r, _ := Select("1password", m, "global") // global should be overridden
	out, _, err := r.ResolveString("op://alexis@portermetrics.com:Private/x/y")
	if err != nil || !strings.Contains(out, "V") {
		t.Fatalf("email account: out=%q err=%v (calls=%v)", out, err, m.calls)
	}
}

func TestSplitAccountRef(t *testing.T) {
	cases := []struct{ in, acct, clean string }{
		{"op://7FWKE:Private/x/y", "7FWKE", "op://Private/x/y"},
		{"op://Private/x/y", "", "op://Private/x/y"},
		{"keeper://uid/custom_field/phone[1][number]", "", "keeper://uid/custom_field/phone[1][number]"},
		{"op://a@b.com:Vault/Item/field", "a@b.com", "op://Vault/Item/field"},
	}
	for _, c := range cases {
		a, cl := splitAccountRef(c.in)
		if a != c.acct || cl != c.clean {
			t.Errorf("splitAccountRef(%q) = (%q,%q), want (%q,%q)", c.in, a, cl, c.acct, c.clean)
		}
	}
}

// 1Password reference schema: op://<vault>/<item>/[section/]<field>?attribute=...
func TestOnePassword_ResolveSectionAndQuery(t *testing.T) {
	m := &mockRunner{
		present: map[string]bool{"op": true},
		outputs: map[string]string{
			"op read -- op://development/GitHub/credentials/personal_token": "ghtok\n",
			"op read -- op://Private/Login/password?attribute=otp":          "123456\n",
		},
	}
	r, _ := Select("1password", m, "")

	out, _vals, err := r.ResolveString("token: op://development/GitHub/credentials/personal_token end")
	n := len(_vals)
	if err != nil || n != 1 || !strings.Contains(out, "ghtok") {
		t.Fatalf("section ref: out=%q n=%d err=%v", out, n, err)
	}
	out2, _, err := r.ResolveString("otp op://Private/Login/password?attribute=otp now")
	if err != nil || !strings.Contains(out2, "123456") || strings.Contains(out2, "op://") {
		t.Fatalf("query ref: out=%q err=%v", out2, err)
	}
}

// Keeper notation predicates (e.g. phone[1][number]) must resolve intact.
func TestKeeper_ResolveNotationPredicate(t *testing.T) {
	ref := "keeper://aj3dg-9ecJuhoa/custom_field/phone[1][number]"
	m := &mockRunner{
		present: map[string]bool{"ksm": true},
		outputs: map[string]string{"ksm secret notation " + ref: "+1555\n"},
	}
	r, _ := Select("keeper", m, "")
	out, _vals, err := r.ResolveString("call " + ref + " please")
	n := len(_vals)
	if err != nil || n != 1 || !strings.Contains(out, "+1555") {
		t.Fatalf("predicate ref: out=%q n=%d err=%v", out, n, err)
	}
}

func TestSelect_Auto_PrefersKeeper(t *testing.T) {
	m := &mockRunner{present: map[string]bool{"ksm": true, "op": true}}
	r, err := Select("auto", m, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.ProviderName() != "keeper" {
		t.Fatalf("auto should prefer keeper, got %q", r.ProviderName())
	}
}

func TestSelect_Auto_FallsBackToOnePassword(t *testing.T) {
	m := &mockRunner{present: map[string]bool{"op": true}}
	r, err := Select("auto", m, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.ProviderName() != "1password" {
		t.Fatalf("auto should fall back to 1password, got %q", r.ProviderName())
	}
}

func TestSelect_Forced1Password(t *testing.T) {
	m := &mockRunner{present: map[string]bool{"ksm": true, "op": true}}
	r, err := Select("1password", m, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.ProviderName() != "1password" {
		t.Fatalf("forced 1password, got %q", r.ProviderName())
	}
}

func TestResolveString_NoProvider_RefErrors(t *testing.T) {
	m := &mockRunner{present: map[string]bool{}} // nothing installed
	r, err := Select("auto", m, "")
	if err != nil {
		t.Fatal(err)
	}
	// A reference present but no vault available must surface an error so the
	// caller can deny the tool call instead of running a broken command.
	if _, _, err := r.ResolveString("use keeper://UID/field/password"); err == nil {
		t.Fatal("expected error when a ref is present but no vault is available")
	}
}

func TestResolveString_NoRefs_NoProvider_OK(t *testing.T) {
	m := &mockRunner{present: map[string]bool{}}
	r, _ := Select("auto", m, "")
	out, _vals, err := r.ResolveString("go build ./...")
	n := len(_vals)
	if err != nil || n != 0 || out != "go build ./..." {
		t.Fatalf("clean string must pass through: out=%q n=%d err=%v", out, n, err)
	}
}
