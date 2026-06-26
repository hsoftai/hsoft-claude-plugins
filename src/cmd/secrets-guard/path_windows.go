//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sys/windows/registry"
)

var vaultPathOnce sync.Once

// augmentVaultPath makes the vault CLI (ksm/op) resolvable even when secrets-guard was
// launched with a STALE PATH — e.g. the Claude Code process started before the Keeper CLI
// was installed (or a GUI app that did not inherit the updated machine PATH), so the
// inherited process PATH lacks the entry. It prepends the persisted Machine + User PATH
// (read from the registry, env vars expanded) to this process's PATH. No-op once `ksm` or
// `op` already resolves, so it is cheap on the common path.
func augmentVaultPath() {
	vaultPathOnce.Do(func() {
		// The Keeper CLI ships `ksm` as `ksm.bat`. A host that spawns the hook with a thin
		// PATHEXT (observed with the VSCode extension host) makes LookPath("ksm") fail even
		// when its directory is on PATH, because .BAT is not in the search extensions. Ensure
		// the standard executable extensions are present so `ksm.bat`/`op.cmd` resolve.
		ensurePathExt()
		// The Keeper CLI ships under two names: the pip console script `ksm` and the
		// standalone release binary `keeper-ksm.exe`. Any of these (or 1Password's `op`)
		// resolving means the PATH is already good.
		for _, bin := range []string{"ksm", "keeper-ksm", "op"} {
			if _, err := exec.LookPath(bin); err == nil {
				return
			}
		}
		var extra []string
		for _, e := range []struct {
			root registry.Key
			sub  string
		}{
			{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`},
			{registry.CURRENT_USER, `Environment`},
		} {
			k, err := registry.OpenKey(e.root, e.sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			if v, _, err := k.GetStringValue("Path"); err == nil && v != "" {
				if exp, eerr := registry.ExpandString(v); eerr == nil {
					v = exp
				}
				extra = append(extra, v)
			}
			k.Close()
		}
		if len(extra) == 0 {
			return
		}
		sep := string(os.PathListSeparator)
		os.Setenv("PATH", strings.Join(extra, sep)+sep+os.Getenv("PATH"))
	})
}

// ensurePathExt guarantees the standard Windows executable extensions are searchable, so a
// CLI shipped as `.bat`/`.cmd` (Keeper's `ksm.bat`) resolves through exec.LookPath even when
// the process inherited an empty or reduced PATHEXT.
func ensurePathExt() {
	const std = ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC"
	cur := os.Getenv("PATHEXT")
	if cur == "" {
		os.Setenv("PATHEXT", std)
		return
	}
	up := strings.ToUpper(cur)
	add := []string{}
	for _, w := range []string{".COM", ".EXE", ".BAT", ".CMD"} {
		if !strings.Contains(up, w) {
			add = append(add, w)
		}
	}
	if len(add) > 0 {
		os.Setenv("PATHEXT", cur+";"+strings.Join(add, ";"))
	}
}
