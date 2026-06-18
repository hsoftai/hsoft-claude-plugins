//go:build !windows

package main

// ensureCredential is a no-op off Windows. The Windows service ingests the Keeper
// credential into its own process environment and a DPAPI-encrypted store; on macOS/Linux
// the service is dev-only and tests supply pre-rendered file content directly.
func ensureCredential() {}
