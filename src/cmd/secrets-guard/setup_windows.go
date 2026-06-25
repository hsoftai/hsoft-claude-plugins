//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
)

// Windows cleanup of legacy components from the old WinFsp/sandbox-dlp service model and
// the field "fake DLP server" workaround. The local model uses none of these.

func sgRoot() string            { return filepath.Join(os.Getenv("LOCALAPPDATA"), "secrets-guard") }
func legacyServiceDir() string  { return filepath.Join(sgRoot(), "sandbox-dlp") }
func fakeServerScript() string  { return filepath.Join(sgRoot(), "fake-dlp-server.ps1") }
func fakeServerLog() string     { return filepath.Join(sgRoot(), "fake-dlp.log") }
func fakeStartupLnk() string {
	return filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "fake-dlp-server.lnk")
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// ps runs a PowerShell snippet best-effort (registry/task/process operations).
func ps(script string) {
	_ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script).Run()
}

// staleComponents lists legacy artifacts present on this machine (for dirty-install report).
func staleComponents() []string {
	var s []string
	if exists(filepath.Join(legacyServiceDir(), "sandbox-dlp.exe")) {
		s = append(s, "old sandbox-dlp service (WinFsp model)")
	}
	if exists(filepath.Join(legacyServiceDir(), "ksm-config.dpapi")) {
		s = append(s, "DPAPI credential store")
	}
	if exists(fakeServerScript()) || exists(fakeStartupLnk()) {
		s = append(s, "fake-dlp-server workaround")
	}
	return s
}

// removeStale stops and removes the legacy service + the fake-dlp workaround. Returns a
// human list of what it cleaned. Best-effort: missing pieces are silently skipped.
func removeStale() []string {
	// Stop any running legacy processes.
	ps(`Get-Process sandbox-dlp -ErrorAction SilentlyContinue | Stop-Process -Force`)
	ps(`Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | ` +
		`Where-Object { $_.CommandLine -like '*fake-dlp-server*' } | ` +
		`ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`)
	// Remove the legacy autostart mechanisms.
	ps(`Unregister-ScheduledTask -TaskName 'secrets-guard sandbox-dlp' -Confirm:$false -ErrorAction SilentlyContinue`)
	ps(`Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'secrets-guard-sandbox-dlp' -ErrorAction SilentlyContinue`)

	var done []string
	if removeIfExists(legacyServiceDir()) {
		done = append(done, "sandbox-dlp service + DPAPI store")
	}
	removeIfExists(fakeServerLog())
	if removeIfExists(fakeServerScript()) {
		done = append(done, "fake-dlp-server script")
	}
	if removeIfExists(fakeStartupLnk()) {
		done = append(done, "fake-dlp-server autostart")
	}
	return done
}

// uninstallEnv removes the FULL secrets-guard footprint (legacy components + the CLI and
// its PATH entry + session caches), leaving the user's vault profile intact.
func uninstallEnv() []string {
	done := removeStale()
	if removeIfExists(installTargetDir()) {
		done = append(done, "secrets-guard CLI binary")
	}
	if removeBinFromUserPath() {
		done = append(done, "user PATH entry")
	}
	for _, pat := range []string{"secrets-guard-sock-*", "secrets-guard-paths-*"} {
		if ms, _ := filepath.Glob(filepath.Join(os.TempDir(), pat)); len(ms) > 0 {
			for _, m := range ms {
				os.RemoveAll(m)
			}
		}
	}
	done = append(done, "session caches & reference ledgers")
	return done
}

// removeBinFromUserPath filters the secrets-guard bin dir out of the user PATH (registry),
// preserving every other entry. Returns true (best-effort).
func removeBinFromUserPath() bool {
	dir := installTargetDir()
	ps("$d='" + dir + "'; $p=[Environment]::GetEnvironmentVariable('Path','User'); " +
		"if($p){ $n=(($p -split ';') | Where-Object { $_ -and ($_ -ne $d) }) -join ';'; " +
		"if($n -ne $p){ [Environment]::SetEnvironmentVariable('Path',$n,'User') } }")
	return true
}
