package vault

import (
	"os/exec"
	"strings"
)

// keeper resolves keeper:// references via the Keeper Secrets Manager CLI.
// Authentication is headless through the KSM_CONFIG (base64) / KSM_TOKEN
// environment variables, which the ksm process reads itself.
type keeper struct{ r Runner }

func newKeeper(r Runner) *keeper { return &keeper{r: r} }

func (k *keeper) Name() string   { return "keeper" }
func (k *keeper) Scheme() string { return "keeper" }

// keeperBins are the known executable names for the Keeper Secrets Manager CLI, in
// preference order. The pip console script (`keeper-secrets-manager-cli`) installs as
// `ksm`; the standalone Windows release ships the binary as `keeper-ksm.exe`. A machine
// may have only one of them on PATH, so we resolve whichever is present — otherwise a
// host with just `keeper-ksm.exe` reports "vault: none" despite a working CLI.
var keeperBins = []string{"ksm", "keeper-ksm"}

// isKeeperBin reports whether name is one of the recognized Keeper CLI executables.
func isKeeperBin(name string) bool {
	for _, b := range keeperBins {
		if name == b {
			return true
		}
	}
	return false
}

// LookKeeper returns the resolved filesystem path of the Keeper CLI (ksm or keeper-ksm)
// and whether one was found on PATH. Used by command-line diagnostics so they recognize
// the standalone `keeper-ksm.exe` as well as the pip `ksm` console script.
func LookKeeper() (string, bool) {
	for _, name := range keeperBins {
		if p, err := exec.LookPath(name); err == nil {
			return p, true
		}
	}
	return "", false
}

// keeperBin returns the first Keeper CLI name resolvable via r, or "ksm" as a stable
// default so error messages and non-Look call sites still name a real candidate.
func keeperBin(r Runner) string {
	for _, name := range keeperBins {
		if r.Look(name) {
			return name
		}
	}
	return keeperBins[0]
}

func (k *keeper) Available() bool {
	for _, name := range keeperBins {
		if k.r.Look(name) {
			return true
		}
	}
	return false
}

// Resolve runs: <ksm|keeper-ksm> secret notation <ref>
// where <ref> is a keeper:// notation string. Output is the secret value.
// Keeper has no multi-account CLI selector, so account is ignored.
func (k *keeper) Resolve(ref, _ string) (string, error) {
	out, err := k.r.Run(keeperBin(k.r), "secret", "notation", ref)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(out, "\r\n"), nil
}
