package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

// ensureVaultCLI makes sure a vault CLI is available for the redaction guard. If a Keeper
// (ksm/keeper-ksm) or 1Password (op) CLI is already on PATH it is a no-op. Otherwise it tries
// to install the Keeper Secrets Manager CLI using the platform's package manager
// (auto-detected). Returns whether a CLI ended up available and a value-free detail line.
func ensureVaultCLI() (bool, string) {
	if _, ok := vault.LookKeeper(); ok {
		return true, "Keeper CLI already on PATH"
	}
	if _, err := exec.LookPath("op"); err == nil {
		return true, "1Password CLI (op) on PATH"
	}

	pm, instCmd := keeperInstallCommand()
	if pm == "" {
		return false, "no supported package manager found (winget/brew/pip3) — install the Keeper Secrets Manager CLI manually"
	}
	fmt.Printf("    installing Keeper CLI via %s ...\n", pm)
	c := exec.Command(instCmd[0], instCmd[1:]...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return false, fmt.Sprintf("%s install failed: %v", pm, err)
	}
	// Refresh PATH so a just-installed CLI is resolvable in this process (Windows: registry).
	augmentVaultPath()
	if _, ok := vault.LookKeeper(); ok {
		return true, "installed via " + pm
	}
	return false, "installed via " + pm + " but not yet on PATH — open a new terminal and re-run `secrets-guard install`"
}

// keeperInstallCommand returns the package manager name and the command to install the Keeper
// Secrets Manager CLI on this OS, or ("","") if none is available.
func keeperInstallCommand() (string, []string) {
	switch runtime.GOOS {
	case "windows":
		if has("winget") {
			return "winget", []string{"winget", "install", "--id", "KeeperSecurity.KeeperSecretsManager",
				"-e", "--silent", "--accept-package-agreements", "--accept-source-agreements"}
		}
	case "darwin":
		if has("brew") {
			return "brew", []string{"brew", "install", "keeper-secrets-manager-cli"}
		}
		if has("pip3") {
			return "pip3", []string{"pip3", "install", "--user", "keeper-secrets-manager-cli"}
		}
	default: // linux and others
		if has("pip3") {
			return "pip3", []string{"pip3", "install", "--user", "keeper-secrets-manager-cli"}
		}
		if has("pip") {
			return "pip", []string{"pip", "install", "--user", "keeper-secrets-manager-cli"}
		}
	}
	return "", nil
}

func has(name string) bool { _, err := exec.LookPath(name); return err == nil }

// promptKeeperToken reads a one-time Keeper token interactively from stdin. Returns "" when
// stdin is not a terminal or the user just pressed Enter (skip).
func promptKeeperToken() string {
	fmt.Println()
	fmt.Println("  To finish setup, paste a Keeper one-time access token (from your Secrets Manager")
	fmt.Println("  application bound to a Shared Folder). Press Enter to skip.")
	fmt.Print("  One-time token: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimSpace(line)
}

// printKeeperSetupSteps prints the Keeper setup instructions (shown when no token is given or
// validation fails). Mirrors the hook's onboarding message.
func printKeeperSetupSteps() {
	fmt.Println("  How to get a token:")
	fmt.Println("    1. In Keeper, create a Shared Folder.")
	fmt.Println("    2. In Keeper Secrets Manager, create an Application and bind that Shared Folder to it.")
	fmt.Println("    3. Generate a one-time access token for the application.")
	fmt.Println("    4. Re-run `secrets-guard install` and paste the token when prompted.")
}
