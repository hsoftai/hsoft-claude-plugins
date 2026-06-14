package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func testServer() *Server {
	return NewServer("secrets-guard", "0.1.0", []Tool{
		{
			Name:        "echo",
			Description: "echoes back",
			Handler: func(args map[string]any) (string, error) {
				return "you said: " + args["msg"].(string), nil
			},
		},
	})
}

// decodeLines parses each non-empty output line as a JSON-RPC response.
func decodeLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var res []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("bad response line %q: %v", ln, err)
		}
		res = append(res, m)
	}
	return res
}

func TestServe_InitializeListCall(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}`,
	}, "\n") + "\n"

	var out strings.Builder
	if err := testServer().Serve(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	resps := decodeLines(t, out.String())
	// initialize + tools/list + tools/call = 3 responses (the notification gets none).
	if len(resps) != 3 {
		t.Fatalf("expected 3 responses, got %d: %s", len(resps), out.String())
	}

	// initialize echoes the client's protocol version.
	init := resps[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocolVersion = %v", init["protocolVersion"])
	}

	// tools/list contains echo.
	tools := resps[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "echo" {
		t.Fatalf("tools/list = %+v", tools)
	}

	// tools/call returns the handler text.
	content := resps[2]["result"].(map[string]any)["content"].([]any)
	if content[0].(map[string]any)["text"] != "you said: hi" {
		t.Fatalf("tools/call = %+v", content)
	}
}

func TestServe_UnknownMethodErrors(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":9,"method":"does/not/exist"}` + "\n"
	var out strings.Builder
	_ = testServer().Serve(strings.NewReader(in), &out)
	resps := decodeLines(t, out.String())
	if len(resps) != 1 || resps[0]["error"] == nil {
		t.Fatalf("expected an error response, got %s", out.String())
	}
}

func TestServe_NotificationGetsNoResponse(t *testing.T) {
	in := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	var out strings.Builder
	_ = testServer().Serve(strings.NewReader(in), &out)
	if strings.TrimSpace(out.String()) != "" {
		t.Fatalf("notification must produce no output, got %q", out.String())
	}
}
