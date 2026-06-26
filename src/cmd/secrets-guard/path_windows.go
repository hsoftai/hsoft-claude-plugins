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
		if _, err := exec.LookPath("ksm"); err == nil {
			return
		}
		if _, err := exec.LookPath("op"); err == nil {
			return
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
