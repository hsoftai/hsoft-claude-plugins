package vault

import "strings"

// onePassword resolves op:// references via the 1Password CLI (`op read`).
// It mirrors the Keeper provider through the same Provider interface so both
// behave identically to the rest of secrets-guard.
//
// account is optional. When the machine has more than one 1Password account
// configured, `op` refuses to guess; setting account makes secrets-guard pass
// `--account <account>` so resolution is unambiguous. (1Password's own
// OP_ACCOUNT environment variable works too, but the explicit option lets you
// fix it centrally in managed-settings.json.)
type onePassword struct {
	r       Runner
	account string
}

func newOnePassword(r Runner, account string) *onePassword {
	return &onePassword{r: r, account: account}
}

func (o *onePassword) Name() string   { return "1password" }
func (o *onePassword) Scheme() string { return "op" }

func (o *onePassword) Available() bool { return o.r.Look("op") }

// Resolve runs `op read [--account <account>] op://<vault>/<item>/<field>`. A
// per-reference account (from op://<account>:…) overrides the configured one.
func (o *onePassword) Resolve(ref, account string) (string, error) {
	if account == "" {
		account = o.account
	}
	args := []string{"read"}
	if account != "" {
		args = append(args, "--account", account)
	}
	args = append(args, ref)
	out, err := o.r.Run("op", args...)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(out, "\r\n"), nil
}
