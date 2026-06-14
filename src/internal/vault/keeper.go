package vault

import "strings"

// keeper resolves keeper:// references via the Keeper Secrets Manager CLI.
// Authentication is headless through the KSM_CONFIG (base64) / KSM_TOKEN
// environment variables, which the ksm process reads itself.
type keeper struct{ r Runner }

func newKeeper(r Runner) *keeper { return &keeper{r: r} }

func (k *keeper) Name() string   { return "keeper" }
func (k *keeper) Scheme() string { return "keeper" }

func (k *keeper) Available() bool { return k.r.Look("ksm") }

// Resolve runs: ksm secret notation <ref>
// where <ref> is a keeper:// notation string. Output is the secret value.
// Keeper has no multi-account CLI selector, so account is ignored.
func (k *keeper) Resolve(ref, _ string) (string, error) {
	out, err := k.r.Run("ksm", "secret", "notation", ref)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(out, "\r\n"), nil
}
