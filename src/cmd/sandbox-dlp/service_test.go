package main

import (
	"os"
	"testing"
	"time"

	"github.com/hsoftai/hsoft-claude-plugins/internal/projection"
)

type allowOracle struct{}

func (allowOracle) InSubtree(int) bool { return true }

// reapOnce must drop execs whose root process is dead OR whose TTL has lapsed, run their
// cleanup, and scrub them from the registry — while leaving healthy execs untouched.
func TestReapOnce_DropsDeadAndExpiredExecs(t *testing.T) {
	s := &Service{reg: projection.New(), execs: map[string]*execEntry{}}

	deadCleaned, expCleaned := false, false
	add := func(id, token string, rootPID int, deadline time.Time, cleaned *bool) {
		s.reg.Register(id, "root", "mp", map[string][]byte{"/x": []byte("v")}, allowOracle{}, token)
		s.execs[id] = &execEntry{rootPID: rootPID, token: token, deadline: deadline, cleanup: func() error {
			if cleaned != nil {
				*cleaned = true
			}
			return nil
		}}
	}
	add("dead", "td", -1, time.Now().Add(time.Hour), &deadCleaned)               // dead pid, TTL ok
	add("exp", "te", os.Getpid(), time.Now().Add(-time.Minute), &expCleaned)     // alive, TTL lapsed
	add("live", "tl", os.Getpid(), time.Now().Add(time.Hour), nil)               // healthy

	s.reapOnce()

	if !deadCleaned || !expCleaned {
		t.Fatalf("dead/expired not reaped: dead=%v exp=%v", deadCleaned, expCleaned)
	}
	if _, ok := s.execs["dead"]; ok {
		t.Fatal("dead exec still tracked")
	}
	if _, ok := s.execs["exp"]; ok {
		t.Fatal("expired exec still tracked")
	}
	if _, ok := s.execs["live"]; !ok {
		t.Fatal("healthy exec was wrongly reaped")
	}
	if s.reg.Active() != 1 {
		t.Fatalf("registry should keep only the healthy exec, got %d active", s.reg.Active())
	}
}
