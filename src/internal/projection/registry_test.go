package projection

import (
	"bytes"
	"path/filepath"
	"sync"
	"testing"
)

// fakeOracle is a test subtree oracle: a fixed set of authorized PIDs.
type fakeOracle struct{ pids map[int]bool }

func (f fakeOracle) InSubtree(pid int) bool { return f.pids[pid] }

func newReg(t *testing.T) (*Registry, string, []byte) {
	t.Helper()
	r := New()
	path := filepath.Join(string(filepath.Separator), "proj", ".env")
	rendered := []byte("PASSWORD=S3cr3tReal\n")
	r.Register("exec1", "/proj", "/mnt/exec1",
		map[string][]byte{path: rendered}, fakeOracle{pids: map[int]bool{1234: true}}, "tok-1")
	return r, path, rendered
}

func TestResolve_AuthorizedServesRendered(t *testing.T) {
	r, path, rendered := newReg(t)
	got, serve := r.Resolve(path, 1234)
	if !serve {
		t.Fatal("authorized caller should be served the rendered bytes")
	}
	if !bytes.Equal(got, rendered) {
		t.Fatalf("rendered mismatch: %q", got)
	}
}

func TestResolve_UnauthorizedPassesThrough(t *testing.T) {
	r, path, _ := newReg(t)
	if _, serve := r.Resolve(path, 9999); serve {
		t.Fatal("a caller outside the subtree must NOT be served the value (pass-through)")
	}
}

func TestResolve_UnregisteredPathPassesThrough(t *testing.T) {
	r, _, _ := newReg(t)
	other := filepath.Join(string(filepath.Separator), "proj", "main.go")
	if _, serve := r.Resolve(other, 1234); serve {
		t.Fatal("a non-ref file must pass through even for an authorized caller")
	}
}

func TestResolve_PathIsCleaned(t *testing.T) {
	r, path, rendered := newReg(t)
	// A messy but equivalent path must still match.
	messy := filepath.Join(filepath.Dir(path), ".", "..", filepath.Base(filepath.Dir(path)), ".env")
	got, serve := r.Resolve(messy, 1234)
	if !serve || !bytes.Equal(got, rendered) {
		t.Fatalf("cleaned path should match: serve=%v got=%q", serve, got)
	}
}

func TestDeregister_WipesAndScrubs(t *testing.T) {
	r, path, rendered := newReg(t)
	// Hold the aliased buffer to confirm it is zeroed in place.
	got, _ := r.Resolve(path, 1234)
	if !r.Deregister("exec1", "tok-1") {
		t.Fatal("deregister with the right token should succeed")
	}
	if _, serve := r.Resolve(path, 1234); serve {
		t.Fatal("after deregister nothing should be served")
	}
	if r.Active() != 0 {
		t.Fatalf("expected 0 active execs, got %d", r.Active())
	}
	// The previously served buffer must be scrubbed (no secret left in RAM).
	if !bytes.Equal(got, make([]byte, len(rendered))) {
		t.Fatalf("rendered buffer not scrubbed after deregister: %q", got)
	}
}

func TestDeregister_WrongTokenIsNoop(t *testing.T) {
	r, path, _ := newReg(t)
	if r.Deregister("exec1", "wrong") {
		t.Fatal("deregister with a wrong token must be rejected")
	}
	if _, serve := r.Resolve(path, 1234); !serve {
		t.Fatal("a rejected deregister must leave the exec active")
	}
}

func TestRegister_ReplaceScrubsOld(t *testing.T) {
	r, path, oldBytes := newReg(t)
	old, _ := r.Resolve(path, 1234)
	// Re-register the same exec with new content; the old buffer must be scrubbed.
	r.Register("exec1", "/proj", "/mnt/exec1",
		map[string][]byte{path: []byte("PASSWORD=Rotated\n")}, fakeOracle{pids: map[int]bool{1234: true}}, "tok-1")
	if !bytes.Equal(old, make([]byte, len(oldBytes))) {
		t.Fatalf("old buffer not scrubbed on replace: %q", old)
	}
	got, serve := r.Resolve(path, 1234)
	if !serve || string(got) != "PASSWORD=Rotated\n" {
		t.Fatalf("replacement not served: serve=%v got=%q", serve, got)
	}
}

func TestResolve_NilOracleFailsClosed(t *testing.T) {
	r := New()
	path := filepath.Join(string(filepath.Separator), "p", ".env")
	r.Register("e", "/p", "/mnt", map[string][]byte{path: []byte("x")}, nil, "t")
	if _, serve := r.Resolve(path, 1); serve {
		t.Fatal("a nil oracle must fail closed (pass-through), never serve a value")
	}
}

func TestConcurrentResolveRegister(t *testing.T) {
	r := New()
	path := filepath.Join(string(filepath.Separator), "p", ".env")
	oracle := fakeOracle{pids: map[int]bool{7: true}}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			r.Register("e", "/p", "/mnt", map[string][]byte{path: []byte("v")}, oracle, "t")
		}(i)
		go func() {
			defer wg.Done()
			_, _ = r.Resolve(path, 7)
		}()
	}
	wg.Wait()
	r.Deregister("e", "t")
}
