// Package mcp is a minimal Model Context Protocol stdio server (JSON-RPC 2.0,
// newline-delimited). It exposes a fixed set of tools so Claude Code can call
// them. secrets-guard uses it to publish vault-catalog tools that return
// references and labels but never secret values.
package mcp

import (
	"bufio"
	"encoding/json"
	"io"
)

// Tool is a callable exposed over MCP.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	// Handler receives the call arguments and returns text content, or an error
	// (reported to the client as an tool error, not a transport error).
	Handler func(args map[string]any) (string, error)
}

// Server serves a set of tools over an MCP stdio transport.
type Server struct {
	name    string
	version string
	tools   []Tool
}

// NewServer builds a Server.
func NewServer(name, version string, tools []Tool) *Server {
	return &Server{name: name, version: version, tools: tools}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve reads JSON-RPC messages from in (one per line) and writes responses to
// out until in is exhausted.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if resp, ok := s.handle(line); ok {
				b, _ := json.Marshal(resp)
				w.Write(b)
				w.WriteByte('\n')
				w.Flush()
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// handle processes one message. The second return is false for notifications
// (no response must be written).
func (s *Server) handle(line []byte) (rpcResponse, bool) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return rpcResponse{}, false
	}
	// Notifications have no id and never get a response.
	isNotification := len(req.ID) == 0

	switch req.Method {
	case "initialize":
		return s.ok(req.ID, s.initializeResult(req.Params)), true
	case "tools/list":
		return s.ok(req.ID, map[string]any{"tools": s.toolList()}), true
	case "tools/call":
		return s.ok(req.ID, s.callTool(req.Params)), true
	case "ping":
		return s.ok(req.ID, map[string]any{}), true
	default:
		if isNotification {
			return rpcResponse{}, false
		}
		return rpcResponse{
			JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: -32601, Message: "method not found: " + req.Method},
		}, true
	}
}

func (s *Server) ok(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func (s *Server) initializeResult(params json.RawMessage) map[string]any {
	version := "2024-11-05"
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(params, &p) == nil && p.ProtocolVersion != "" {
		version = p.ProtocolVersion
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": s.name, "version": s.version},
	}
}

func (s *Server) toolList() []map[string]any {
	out := make([]map[string]any, 0, len(s.tools))
	for _, t := range s.tools {
		schema := t.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": schema,
		})
	}
	return out
}

func (s *Server) callTool(params json.RawMessage) map[string]any {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return toolError("invalid tool call params")
	}
	for _, t := range s.tools {
		if t.Name == p.Name {
			text, err := t.Handler(p.Arguments)
			if err != nil {
				return toolError(err.Error())
			}
			return map[string]any{
				"content": []map[string]any{{"type": "text", "text": text}},
			}
		}
	}
	return toolError("unknown tool: " + p.Name)
}

func toolError(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": "error: " + msg}},
		"isError": true,
	}
}
