//go:build windows

package vault

import (
	"os/exec"
	"strings"
	"syscall"
)

// vaultCommand builds the process invocation for a vault CLI call on Windows.
//
// A CLI installed as a batch wrapper — e.g. Keeper's `ksm.bat`, whose entire body is
// `keeper-ksm.exe %*` with no `@echo off` — is run by cmd.exe with command-echo ON, so
// cmd prints the expanded command line to stdout before the program's own output. That
// echo would be captured as part of the resolved secret and corrupt it. Running the
// wrapper through `cmd /d /q /c` turns echo OFF (/q), skips AutoRun (/d), and yields only
// the program's real output. Real `.exe` CLIs (e.g. 1Password's `op`) are run directly.
func vaultCommand(name string, args []string) *exec.Cmd {
	if full, err := exec.LookPath(name); err == nil && isBatchWrapper(full) {
		// cmd.exe /c treats everything after it as one command line that it re-parses
		// itself. Letting Go quote each arg independently can be re-split by cmd into
		// the wrong words when the path or an arg contains spaces or cmd metacharacters.
		// So we build one cmd-quoted command line and hand it over verbatim via CmdLine,
		// bypassing Go's argv quoting; cmd then parses exactly what we intended.
		cmd := exec.Command("cmd")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CmdLine: "cmd /d /q /c " + quoteArgsForCmd(full, args),
		}
		return cmd
	}
	return exec.Command(name, args...)
}

func isBatchWrapper(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".bat") || strings.HasSuffix(lower, ".cmd")
}

// quoteArgsForCmd builds a single command line (program + args) using cmd.exe's quoting
// rules. Any token containing whitespace or a cmd metacharacter is wrapped in double quotes
// (cmd does not strip caret escapes inside quotes, so quoting alone neutralizes them); an
// embedded double quote is doubled ("") so the surrounding quotes stay balanced.
func quoteArgsForCmd(program string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quoteForCmd(program))
	for _, a := range args {
		parts = append(parts, quoteForCmd(a))
	}
	return strings.Join(parts, " ")
}

func quoteForCmd(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t&|<>^%\"\n\r") && !strings.HasSuffix(s, "\\") {
		return s
	}
	// Split off any run of trailing backslashes and re-attach them OUTSIDE the closing
	// quote. cmd.exe has no escape mechanism for a literal backslash, so doubling one
	// inside the quotes would corrupt the value (e.g. `C:\dir\` -> `C:\dir\\`). The
	// program's argv parser treats backslashes as literal unless they precede a `"`; left
	// outside the quotes they are followed by the argument separator, so each backslash is
	// passed through verbatim.
	body := s
	trailing := 0
	for strings.HasSuffix(body, `\`) {
		body = body[:len(body)-1]
		trailing++
	}
	// Within the quotes escape embedded double quotes by doubling them ("" ), which is
	// cmd.exe's quoting mechanism. cmd has no backslash escape, so a `\"` would toggle
	// cmd's quote state off and leave the rest of the token unquoted; doubling keeps the
	// surrounding quotes balanced for cmd and for the program's argv parser.
	escaped := strings.ReplaceAll(body, `"`, `""`)
	return `"` + escaped + `"` + strings.Repeat(`\`, trailing)
}
