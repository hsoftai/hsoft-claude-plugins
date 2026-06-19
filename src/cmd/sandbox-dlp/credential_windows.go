//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

var pathOnce sync.Once

// augmentMachinePath ensures the vault CLI (ksm/op) is resolvable by the service even when
// it was launched with a stale PATH (e.g. a logon task started before the CLI was added to
// the machine PATH, or a hook-spawned restart inheriting Claude Code's environment). It
// prepends the persisted Machine and User PATH (read from the registry, env vars expanded)
// to this process's PATH. Without this the service can silently fail to load the vault
// values; the guard then fails closed, but this keeps it WORKING in the normal case.
func augmentMachinePath() {
	pathOnce.Do(func() {
		if _, err := exec.LookPath("ksm"); err == nil {
			return // already resolvable
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

// This file makes the sandbox-dlp service the SOLE holder of the Keeper credential on
// Windows. The credential lives only in (a) the service's own process environment
// (KSM_CONFIG — private to the process, unreadable by other processes) and (b) a
// DPAPI-encrypted file in the service's per-user directory. The local `ksm` profile (in
// the OS Credential Manager, usable by ANY process) is removed once the credential has
// been ingested and verified, so a bare `ksm` call — by the agent or any other process —
// can no longer resolve. Only this service can, and it serves rendered values exclusively
// to the authorized command subtree (never back over the control channel).

var (
	modcrypt32         = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtect   = modcrypt32.NewProc("CryptProtectData")
	procCryptUnprotect = modcrypt32.NewProc("CryptUnprotectData")
	modkernel32cred    = windows.NewLazySystemDLL("kernel32.dll")
	procLocalFree      = modkernel32cred.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func (b dataBlob) bytes() []byte {
	if b.cbData == 0 || b.pbData == nil {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

// dpapiProtect encrypts plain with the CURRENT-USER DPAPI master key (flags=0). Only the
// same user on the same machine can decrypt it.
func dpapiProtect(plain []byte) ([]byte, error) {
	in := newBlob(plain)
	var out dataBlob
	r, _, err := procCryptProtect.Call(
		uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return out.bytes(), nil
}

func dpapiUnprotect(enc []byte) ([]byte, error) {
	in := newBlob(enc)
	var out dataBlob
	r, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return out.bytes(), nil
}

func credStorePath() string {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "secrets-guard", "sandbox-dlp")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "ksm-config.dpapi")
}

var credOnce sync.Once

// ensureCredential provisions KSM_CONFIG into THIS process's environment exactly once.
// Order: (1) already set (e.g. by MDM) → done; (2) load the DPAPI store; (3) ingest the
// local ksm profile (export → store → verify → delete the global profile). The destructive
// delete only happens after the DPAPI store round-trips AND the config is confirmed to
// resolve, so it can never leave the service without a working credential.
func ensureCredential() {
	augmentMachinePath() // make ksm/op resolvable even under a stale launch PATH
	credOnce.Do(func() {
		// 1) Externally provisioned (e.g. MDM managed-settings): use it as-is.
		if os.Getenv("KSM_CONFIG") != "" {
			return
		}
		store := credStorePath()

		// 2) Already ingested on a prior run: load the DPAPI store and we're done — the
		// global profile was already purged at first ingest, so no ksm calls are needed
		// here (keeps service startup fast).
		if enc, err := os.ReadFile(store); err == nil {
			if dec, derr := dpapiUnprotect(enc); derr == nil && len(dec) > 0 {
				os.Setenv("KSM_CONFIG", string(dec))
				return
			}
		}

		// 3) First run: ingest the local ksm profile once.
		cfg, err := vault.ExportKeeperConfig()
		dbg("ensureCredential: export len=%d err=%v", len(cfg), err)
		if err != nil || cfg == "" {
			return // no credential available yet
		}
		// Confirm it resolves BEFORE touching the global profile, so we can never strand
		// the service without a working credential.
		os.Setenv("KSM_CONFIG", cfg)
		if verr := vault.VerifyKeeperConfig(); verr != nil {
			dbg("ensureCredential: verify err=%v", verr)
			os.Unsetenv("KSM_CONFIG")
			return
		}
		// Persist a durable, user-DPAPI-encrypted copy so restarts need no re-provisioning.
		persisted := false
		if enc, perr := dpapiProtect([]byte(cfg)); perr == nil && os.WriteFile(store, enc, 0o600) == nil {
			if rt, rerr := os.ReadFile(store); rerr == nil {
				if dec, derr := dpapiUnprotect(rt); derr == nil && string(dec) == cfg {
					persisted = true
				}
			}
		}
		// Remove the global ksm profile so a bare `ksm` by ANY other process can no longer
		// resolve — only this service can, via KSM_CONFIG. The delete MUST run with
		// KSM_CONFIG unset, or ksm operates on the env config and the keyring profile
		// survives. Only purge once we hold a durable copy.
		os.Unsetenv("KSM_CONFIG")
		if persisted {
			dbg("ensureCredential: delete profile err=%v", vault.DeleteKeeperProfile())
		}
		os.Setenv("KSM_CONFIG", cfg) // restore for the service's own resolution
	})
}
