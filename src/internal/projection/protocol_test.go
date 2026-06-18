package projection

import (
	"bytes"
	"path/filepath"
	"runtime"
	"testing"
)

func absUnder(root, name string) string { return filepath.Join(root, name) }

// absTest builds an absolute path that is valid on every OS (filepath.IsAbs is true):
// a bare leading separator is NOT absolute on Windows, which needs a drive letter.
func absTest(parts ...string) string {
	root := string(filepath.Separator)
	if runtime.GOOS == "windows" {
		root = `C:\`
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

func validReq(t *testing.T) RegisterRequest {
	t.Helper()
	root := absTest("proj")
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	return RegisterRequest{
		ExecID:     "exec-1",
		Root:       root,
		Mountpoint: absTest("mnt", "exec-1"),
		Files:      []RenderedFile{{Path: absUnder(root, ".env"), Content: []byte("PASSWORD=val\n")}},
		RootPID:    4321,
		Token:      tok,
		TTLSeconds: 30,
	}
}

func TestNewToken_UniqueAndSized(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) < 40 {
			t.Fatalf("token too short: %q", tok)
		}
		if seen[tok] {
			t.Fatalf("token collision: %q", tok)
		}
		seen[tok] = true
	}
}

func TestValidate_Accepts(t *testing.T) {
	if err := validReq(t).Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

func TestValidate_Rejects(t *testing.T) {
	cases := map[string]func(*RegisterRequest){
		"empty exec":    func(r *RegisterRequest) { r.ExecID = "" },
		"empty token":   func(r *RegisterRequest) { r.Token = "" },
		"bad pid":       func(r *RegisterRequest) { r.RootPID = 0 },
		"relative root": func(r *RegisterRequest) { r.Root = "proj" },
		"no files":      func(r *RegisterRequest) { r.Files = nil },
		"relative file": func(r *RegisterRequest) { r.Files = []RenderedFile{{Path: "rel.env", Content: []byte("x")}} },
		"escaping file": func(r *RegisterRequest) {
			r.Files = []RenderedFile{{Path: filepath.Join(r.Root, "..", "outside.env"), Content: []byte("x")}}
		},
	}
	for name, mut := range cases {
		req := validReq(t)
		mut(&req)
		if err := req.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	req := validReq(t)
	b, err := Encode(req)
	if err != nil {
		t.Fatal(err)
	}
	var got RegisterRequest
	if err := Decode(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.ExecID != req.ExecID || got.Token != req.Token || got.RootPID != req.RootPID {
		t.Fatalf("scalar fields lost in round-trip: %+v", got)
	}
	if len(got.Files) != 1 || got.Files[0].Path != req.Files[0].Path ||
		!bytes.Equal(got.Files[0].Content, req.Files[0].Content) {
		t.Fatalf("rendered file lost in round-trip: %+v", got.Files)
	}
}

func TestEncodeDecode_ScanRoundTrip(t *testing.T) {
	req := ControlRequest{Op: OpScan, Scan: &ScanRequest{Text: "secret=hunter2"}}
	b, err := Encode(req)
	if err != nil {
		t.Fatal(err)
	}
	var got ControlRequest
	if err := Decode(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Op != OpScan || got.Scan == nil || got.Scan.Text != "secret=hunter2" {
		t.Fatalf("scan request lost in round-trip: %+v", got)
	}
	// And the scan reply fields.
	rb, _ := Encode(Response{OK: true, Found: true, Redacted: "secret=[REDACTED]"})
	var resp Response
	if err := Decode(rb, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || !resp.Found || resp.Redacted != "secret=[REDACTED]" {
		t.Fatalf("scan reply lost in round-trip: %+v", resp)
	}
}

func TestApply_FeedsRegistry(t *testing.T) {
	req := validReq(t)
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	reg := New()
	req.Apply(reg, fakeOracle{pids: map[int]bool{req.RootPID: true}})

	got, serve := reg.Resolve(req.Files[0].Path, req.RootPID)
	if !serve || !bytes.Equal(got, req.Files[0].Content) {
		t.Fatalf("registered file not served to the subtree: serve=%v got=%q", serve, got)
	}
	if _, serve := reg.Resolve(req.Files[0].Path, 1); serve {
		t.Fatal("a non-subtree caller must not be served")
	}
	if !reg.Deregister(req.ExecID, req.Token) {
		t.Fatal("deregister with the request token should succeed")
	}
}
