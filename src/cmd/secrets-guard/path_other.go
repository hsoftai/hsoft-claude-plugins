//go:build !windows

package main

// On macOS/Linux the launching shell's PATH already reflects installed CLIs, so no
// registry-based augmentation is needed.
func augmentVaultPath() {}
