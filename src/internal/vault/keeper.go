package vault

import (
	"os"
	"os/exec"
	"path/filepath"
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

// keeperINIArgs returns the global `--ini-file` flag (as CLI args) to prepend to a Keeper
// CLI invocation so an existing profile is found regardless of the process working
// directory. ksm only auto-discovers keeper.ini in the CURRENT directory, so a profile
// created with `ksm profile init` from the user's home (the common case) is invisible when
// the hook runs from a project directory — which made secrets-guard re-prompt for a token
// and fail-closed even though a working profile was present. Resolution order:
//   - KSM_CONFIG (base64) set -> nil (the CLI reads the env config directly; no INI needed)
//   - KSM_INI_FILE set        -> use it verbatim
//   - otherwise               -> auto-discover the user's keeper.ini (see discoverKeeperINI)
//
// Returns nil when none applies, letting ksm fall back to its own current-directory lookup.
func keeperINIArgs() []string {
	if os.Getenv("KSM_CONFIG") != "" {
		return nil
	}
	ini := os.Getenv("KSM_INI_FILE")
	if ini == "" {
		ini = discoverKeeperINI()
	}
	if ini == "" {
		return nil
	}
	return []string{"--ini-file", ini}
}

// discoverKeeperINI returns the path of an existing per-user Keeper config file, probing the
// standard locations where `ksm profile init` stores keeper.ini, or "" if none is found.
func discoverKeeperINI() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	for _, p := range []string{
		filepath.Join(home, ".keeper", "keeper.ini"),
		filepath.Join(home, "keeper.ini"),
	} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// isKeeperBin reports whether name is one of the recognized Keeper CLI executables.
func isKeeperBin(name string) bool {
	for _, b := range keeperBins {
		if name == b {
			return true
		}
	}
	return false
}

// InitKeeperProfile runs `<ksm> profile init -t <token>` to create the local Keeper Secrets
// Manager profile, letting the CLI store its config in its default location (no --ini-file
// injection, which matches the behavior that works across versions). Returns the CLI's
// combined output (status text, never a secret value) and any error.
func InitKeeperProfile(token string) (string, error) {
	out, err := vaultCommand(keeperBin(execRunner{}), []string{"profile", "init", "-t", token}).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// KeeperCLIName returns the Keeper CLI executable name resolvable on PATH (ksm or
// keeper-ksm), or "ksm" as a default.
func KeeperCLIName() string { return keeperBin(execRunner{}) }

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
