package main

// Install/trigger flow for the Windows kernel-DLP service (sandbox-dlp + WinFsp).
//
// The plugin ships the secrets-guard binary; the kernel-DLP *service* and its driver
// (WinFsp) are a separate, manually-installed system component, because a kernel driver
// can never be installed silently. At SessionStart on Windows, if kernel DLP is enabled
// and the service is not answering, secrets-guard surfaces a one-time, throttled notice
// and (best-effort) launches the installer, which prompts for elevation (UAC). It never
// installs silently and never blocks the session.
//
// macOS/Linux need nothing here: macOS uses the in-place renderer, Linux the mount
// namespace.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hsoftai/hsoft-claude-plugins/internal/config"
	"github.com/hsoftai/hsoft-claude-plugins/internal/dlpipc"
	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

// defaultDLPBase is the release asset base URL the installer is fetched from. Override
// with the dlp_install_source option for air-gapped/on-prem mirrors.
const defaultDLPBase = "https://github.com/hsoftai/hsoft-claude-plugins/releases/latest/download"

// installerAsset is the file fetched and launched (a signed PowerShell installer that
// installs WinFsp + the sandbox-dlp per-user service). A signed MSI can replace it.
const installerAsset = "sandbox-dlp-setup.ps1"

// runDLPStatus implements `secrets-guard dlp-status`.
func runDLPStatus() {
	if dlpipc.Healthy() {
		resp, _ := dlpipc.Call(projection.ControlRequest{Op: projection.OpStatus})
		fmt.Printf("sandbox-dlp: running (active=%d driver=%s)\n", resp.Active, resp.Driver)
		os.Exit(0)
	}
	fmt.Println("sandbox-dlp: not running")
	if runtime.GOOS != "windows" {
		fmt.Println("  note: the kernel-DLP service is Windows-only;",
			"macOS uses the in-place renderer and Linux the mount namespace.")
	} else {
		fmt.Println("  install it with: secrets-guard dlp-install")
	}
	os.Exit(1)
}

// runDLPInstall implements `secrets-guard dlp-install`.
func runDLPInstall(cfg config.Config) {
	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "secrets-guard: the kernel-DLP service is only used on Windows.")
		os.Exit(1)
	}
	if err := installSandboxDLP(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard dlp-install:", err)
		os.Exit(1)
	}
	fmt.Println("secrets-guard: launched the sandbox-dlp installer (approve the elevation prompt).")
}

// maybeTriggerDLPInstall runs at SessionStart. On Windows, when kernel DLP is enabled but
// the service is absent, it emits a one-time (throttled) notice and best-effort launches
// the installer. Never silent, never blocking.
func maybeTriggerDLPInstall(cfg config.Config) {
	if runtime.GOOS != "windows" || cfg.KernelDLP == "off" || cfg.IsCowork {
		return
	}
	if dlpipc.Healthy() {
		return
	}
	if installAttemptedRecently() {
		return
	}
	markInstallAttempt()
	fmt.Fprintln(os.Stderr, "secrets-guard: kernel-DLP (sandbox-dlp + WinFsp) is not installed; "+
		"file rendering falls back to in-place. Installing now (approve the elevation prompt) "+
		"or run: secrets-guard dlp-install")
	if err := installSandboxDLP(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "secrets-guard: could not launch installer:", err)
	}
}

// installSandboxDLP downloads the installer (checksum-verified when a .sha256 is present)
// and launches it elevated via UAC. It returns once the installer has been started; the
// install itself proceeds in the elevated process.
func installSandboxDLP(cfg config.Config) error {
	base := strings.TrimRight(cfg.DLPInstallSource, "/")
	if base == "" {
		base = defaultDLPBase
	}
	dst := filepath.Join(os.TempDir(), installerAsset)
	if err := downloadVerified(base+"/"+installerAsset, base+"/"+installerAsset+".sha256", dst); err != nil {
		return err
	}
	// Launch elevated. Start-Process -Verb RunAs raises the UAC prompt.
	ps := fmt.Sprintf(
		"Start-Process -Verb RunAs -FilePath powershell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','%s')",
		dst)
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	return cmd.Start()
}

// downloadVerified fetches url to dst. If a sha256 sidecar is reachable, the download is
// verified against it (fail-closed); if the sidecar is absent it proceeds (best-effort,
// suitable for dev), which the production signed-MSI path should tighten to mandatory.
func downloadVerified(url, shaURL, dst string) error {
	body, err := httpGet(url)
	if err != nil {
		return err
	}
	if want, ok := fetchSha(shaURL); ok {
		got := sha256.Sum256(body)
		if !strings.EqualFold(hex.EncodeToString(got[:]), want) {
			return fmt.Errorf("installer checksum mismatch (refusing to run)")
		}
	}
	return os.WriteFile(dst, body, 0o600)
}

func httpGet(url string) ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func fetchSha(url string) (string, bool) {
	b, err := httpGet(url)
	if err != nil {
		return "", false
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return "", false
	}
	return f[0], true
}

// --- one-time-per-day throttle for the SessionStart auto-trigger ---

func installStampPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	d := filepath.Join(dir, "secrets-guard")
	_ = os.MkdirAll(d, 0o700)
	return filepath.Join(d, "dlp-install-attempt")
}

func installAttemptedRecently() bool {
	fi, err := os.Stat(installStampPath())
	return err == nil && time.Since(fi.ModTime()) < 24*time.Hour
}

func markInstallAttempt() {
	_ = os.WriteFile(installStampPath(), []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
}
