//go:build !darwin && !windows

package main

import "github.com/hsoftai/hsoft-claude-plugins/internal/projection"

// failClosedOracle authorizes nothing. It is the placeholder subtree oracle on
// platforms whose real oracle is not implemented yet (Windows will use a Job Object +
// IsProcessInJob). Failing closed means the provider can mount but only ever serves the
// original references — never a value — so an unfinished platform can never leak.
type failClosedOracle struct{}

func (failClosedOracle) InSubtree(int) bool { return false }

func newSubtreeOracle(int) projection.SubtreeOracle { return failClosedOracle{} }
