package integration_test

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

type mcpSession struct {
	t      *testing.T
	stdin  io.WriteCloser
	reader *bufio.Reader
	nextID int
}

func startMCP(t *testing.T, binary, apiURL string) *mcpSession {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), binary, "mcp-server")
	cmd.Env = append(cmd.Environ(),
		"TAILSCALE_API_KEY="+testAPIKey, "TAILSCALE_TAILNET="+testTailnet, "TAILSCALE_API_URL="+apiURL)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	session := &mcpSession{t: t, stdin: stdin, reader: bufio.NewReader(stdout)}
	session.call("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "tsacl-test", "version": "0"},
	})
	session.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return session
}

func (s *mcpSession) send(message map[string]any) {
	s.t.Helper()
	line, err := json.Marshal(message)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err = s.stdin.Write(append(line, '\n')); err != nil {
		s.t.Fatal(err)
	}
}

func (s *mcpSession) call(method string, params map[string]any) json.RawMessage {
	s.t.Helper()
	s.nextID++
	s.send(map[string]any{"jsonrpc": "2.0", "id": s.nextID, "method": method, "params": params})
	for {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			s.t.Fatalf("reading %s response: %v", method, err)
		}
		var response struct {
			ID     *int            `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err = json.Unmarshal(line, &response); err != nil {
			s.t.Fatalf("stdout is not a JSON-RPC message (protocol corrupted): %v\n%s", err, line)
		}
		if response.ID == nil || *response.ID != s.nextID {
			continue
		}
		if len(response.Error) != 0 {
			s.t.Fatalf("%s: %s", method, response.Error)
		}
		return response.Result
	}
}

type toolResult struct {
	IsError bool `json:"isError"`
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

func (s *mcpSession) tool(name string, arguments map[string]any) toolResult {
	s.t.Helper()
	var result toolResult
	raw := s.call("tools/call", map[string]any{"name": name, "arguments": arguments})
	if err := json.Unmarshal(raw, &result); err != nil {
		s.t.Fatal(err)
	}
	return result
}

func (r toolResult) text() string {
	var text strings.Builder
	for _, content := range r.Content {
		text.WriteString(content.Text)
	}
	return text.String()
}

func TestMCPServerServesTheCommandTree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	binary := buildTSACL(t, dir)
	policy := writePolicy(t, dir, "acl.hujson", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	t.Cleanup(server.Close)
	session := startMCP(t, binary, server.URL)

	var listed struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(session.call("tools/list", map[string]any{}), &listed); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range listed.Tools {
		names[tool.Name] = true
	}
	for _, parent := range []string{
		"grant", "group", "ipset", "ssh", "nodeattr", "tag-owner", "host", "posture", "auto-approver",
		"external-tailnet",
	} {
		if names["tsacl-"+parent] {
			t.Errorf("noun parent %q is exposed as a tool", parent)
		}
	}
	for _, want := range []string{"tsacl-check", "tsacl-test", "tsacl-upload", "tsacl-grant-add"} {
		if !names[want] {
			t.Errorf("tool %q missing from %v", want, names)
		}
	}

	allowed := session.tool("tsacl-check", map[string]any{"file": policy, "src": "a@example.com", "dst": "b:22"})
	if allowed.IsError || !strings.Contains(allowed.text(), `"command": "check"`) {
		t.Errorf("check = %+v, want the result envelope", allowed)
	}

	refused := session.tool("tsacl-upload", map[string]any{"file": policy, "accept-remote-changes": true})
	if !refused.IsError || !strings.Contains(refused.text(), "confirmation_required") {
		t.Errorf("upload without yes = %+v, want confirmation_required", refused)
	}
	if requests.Load() != 0 {
		t.Errorf("upload sent %d requests before approval", requests.Load())
	}

	watch := session.tool("tsacl-test", map[string]any{"file": policy, "watch": true})
	if !watch.IsError || !strings.Contains(watch.text(), "cannot run under mcp-server") {
		t.Errorf("test --watch = %+v, want a refusal", watch)
	}

	closed := writePolicy(t, dir, "closed.hujson", `{"grants": [{"src": ["tag:x"], "dst": ["tag:y"], "ip": ["*"]}]}`)
	denied := session.tool("tsacl-check", map[string]any{"file": closed, "src": "a@example.com", "dst": "b:22"})
	if !denied.IsError || !strings.Contains(denied.text(), `"access"`) || !strings.Contains(denied.text(), "deny") {
		t.Errorf("verdict error lost its envelope: %s", denied.text())
	}
}

func TestMCPCallsDoNotShareFlagState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	binary := buildTSACL(t, dir)
	first := writePolicy(t, dir, "first.hujson", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`)
	second := writePolicy(t, dir, "second.hujson", `{"grants": [{"src": ["tag:x"], "dst": ["tag:y"], "ip": ["*"]}]}`)
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	session := startMCP(t, binary, server.URL)

	args := func(file string) map[string]any {
		return map[string]any{"file": file, "src": "a@example.com", "dst": "b:22"}
	}
	if result := session.tool("tsacl-check", args(first)); result.IsError {
		t.Fatalf("first call = %s", result.text())
	}
	if result := session.tool("tsacl-check", args(second)); !result.IsError {
		t.Errorf("second call reused the first call's policy: %s", result.text())
	}
	missing := session.tool("tsacl-check", map[string]any{"src": "a@example.com", "dst": "b:22"})
	if strings.Contains(missing.text(), "first.hujson") || strings.Contains(missing.text(), "second.hujson") {
		t.Errorf("a call without file inherited an earlier call's file: %s", missing.text())
	}
}
