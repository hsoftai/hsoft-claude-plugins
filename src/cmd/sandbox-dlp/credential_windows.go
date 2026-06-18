//go:build windows

package main

import (
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/hsoftai/hsoft-claude-plugins/internal/vault"
)

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
	credOnce.Do(func() {
		store := credStorePath()

		// Obtain the credential from the first available source:
		//   1) KSM_CONFIG already in the environment (e.g. provisioned by MDM),
		//   2) the previously-ingested DPAPI store,
		//   3) a one-time export of the local ksm profile (keyring).
		cfg := os.Getenv("KSM_CONFIG")
		if cfg == "" {
			if enc, err := os.ReadFile(store); err == nil {
				if dec, derr := dpapiUnprotect(enc); derr == nil && len(dec) > 0 {
					cfg = string(dec)
				}
			}
		}
		if cfg == "" {
			exported, err := vault.ExportKeeperConfig()
			dbg("ensureCredential: export len=%d err=%v", len(exported), err)
			if err != nil || exported == "" {
				return // no credential available yet
			}
			cfg = exported
		}

		// Confirm the credential resolves (with KSM_CONFIG set) BEFORE touching anything,
		// so we can never strand the service without a working credential.
		os.Setenv("KSM_CONFIG", cfg)
		if verr := vault.VerifyKeeperConfig(); verr != nil {
			dbg("ensureCredential: verify err=%v", verr)
			os.Unsetenv("KSM_CONFIG")
			return
		}

		// Persist a durable, user-DPAPI-encrypted copy so restarts need no re-provisioning.
		persisted := false
		if enc, err := dpapiProtect([]byte(cfg)); err == nil && os.WriteFile(store, enc, 0o600) == nil {
			if rt, rerr := os.ReadFile(store); rerr == nil {
				if dec, derr := dpapiUnprotect(rt); derr == nil && string(dec) == cfg {
					persisted = true
				}
			}
		}

		// Remove the global ksm profile so a bare `ksm` by ANY other process can no longer
		// resolve — only this service can, via KSM_CONFIG. The delete MUST run with
		// KSM_CONFIG unset, or ksm operates on the env config and the keyring profile
		// survives. Only purge once we hold a durable copy. Idempotent.
		os.Unsetenv("KSM_CONFIG")
		if persisted {
			derr := vault.DeleteKeeperProfile()
			dbg("ensureCredential: delete profile err=%v", derr)
		}
		os.Setenv("KSM_CONFIG", cfg) // restore for the service's own resolution
	})
}
