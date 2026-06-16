//go:build darwin

package main

import (
	"os"
	"os/exec"
	"testing"
)

func TestSubtreeOracle_SelfIsRoot(t *testing.T) {
	o := newSubtreeOracle(os.Getpid())
	if !o.InSubtree(os.Getpid()) {
		t.Fatal("a process must be in its own subtree")
	}
}

func TestSubtreeOracle_ChildIsMember(t *testing.T) {
	// Spawn a real child of this test process; its ancestry must reach us.
	c := exec.Command("/bin/sleep", "30")
	if err := c.Start(); err != nil {
		t.Fatalf("spawn child: %v", err)
	}
	defer func() { _ = c.Process.Kill(); _, _ = c.Process.Wait() }()

	o := newSubtreeOracle(os.Getpid())
	if !o.InSubtree(c.Process.Pid) {
		t.Fatalf("child pid %d should be in the subtree of root %d", c.Process.Pid, os.Getpid())
	}
}

func TestSubtreeOracle_UnrelatedIsNotMember(t *testing.T) {
	o := newSubtreeOracle(os.Getpid())
	// launchd (pid 1) is never a descendant of us.
	if o.InSubtree(1) {
		t.Fatal("pid 1 must not be in our subtree")
	}
	// We are not in the subtree of an unrelated child root.
	c := exec.Command("/bin/sleep", "30")
	if err := c.Start(); err != nil {
		t.Fatalf("spawn child: %v", err)
	}
	defer func() { _ = c.Process.Kill(); _, _ = c.Process.Wait() }()
	o2 := newSubtreeOracle(c.Process.Pid)
	if o2.InSubtree(os.Getpid()) {
		t.Fatal("the parent must not be in a child's subtree")
	}
}

func TestSubtreeOracle_FailsClosedOnBadInput(t *testing.T) {
	if newSubtreeOracle(0).InSubtree(os.Getpid()) {
		t.Fatal("root<=0 must fail closed")
	}
	if newSubtreeOracle(os.Getpid()).InSubtree(0) {
		t.Fatal("pid<=0 must fail closed")
	}
}
