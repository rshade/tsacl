package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rshade/tsacl/internal/observedstate"
)

func hashFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(sha256.New().Sum(data))
}

func TestDryRunLeavesPolicyAndStateUntouched(t *testing.T) {
	t.Parallel()
	const seed = `{"groups": {"group:eng": ["a@example.com"]}, "grants": []}`
	testCases := []struct {
		name string
		args []string
		diff bool
		// rejected names a rehearsal that must fail exactly as a real run would.
		rejected bool
	}{
		{
			"grant add",
			[]string{"grant", "add", "--src", "group:eng", "--dst", "tag:web", "--ip", "tcp:443"},
			true,
			false,
		},
		{"group add", []string{"group", "add", "--name", "group:ops", "--member", "b@example.com"}, true, false},
		{"host set", []string{"host", "set", "web", "100.64.0.10"}, true, false},
		{"ipset add", []string{"ipset", "add", "--name", "ipset:lan", "--cidr", "10.0.0.0/8"}, true, false},
		{"grant remove out of range", []string{"grant", "remove", "--index", "5"}, false, true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, seed)
			if err := observedstate.Record(path, "example.com", `"etag-1"`); err != nil {
				t.Fatal(err)
			}
			policyBefore, stateBefore := hashFile(t, path), hashFile(t, observedstate.Path(path))

			var stdout, stderr strings.Builder
			args := append([]string{"--format", "json", "--dry-run", "--file", path}, testCase.args...)
			err := run(context.Background(), args, func(string) string { return "" }, nil, "", &stdout, &stderr)
			if testCase.rejected != (err != nil) {
				t.Fatalf("run = %v (stderr %q), want rejection = %v", err, stderr.String(), testCase.rejected)
			}
			if hashFile(t, path) != policyBefore || hashFile(t, observedstate.Path(path)) != stateBefore {
				t.Error("dry-run changed the policy or state file")
			}
			if err != nil {
				return
			}
			assertDryRunEnvelope(t, stdout.String(), path, testCase.diff)
		})
	}
}

func assertDryRunEnvelope(t *testing.T, stdout, path string, wantDiff bool) {
	t.Helper()
	var res result
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if !res.DryRun || res.File != path || strings.Contains(res.Message, "tsacl-dry-run") {
		t.Errorf("envelope = %+v, want dry_run with the real path", res)
	}
	if wantDiff && !strings.Contains(res.Diff, "+") {
		t.Errorf("diff = %q, want the would-be change", res.Diff)
	}
}

func TestDryRunInitCreatesNothing(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	var stdout strings.Builder
	err := run(context.Background(), []string{"--format", "json", "--dry-run", "--file", path, "init"},
		func(string) string { return "" }, nil, "", &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("init --dry-run created %s (%v)", path, statErr)
	}
}

func TestDryRunMergeWritesNothing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base, add, out := filepath.Join(
		dir,
		"base.hujson",
	), filepath.Join(
		dir,
		"add.hujson",
	), filepath.Join(
		dir,
		"out.hujson",
	)
	writeTestPolicy(t, base, `{"grants": []}`)
	writeTestPolicy(t, add, `{"groups": {"group:x": ["a@example.com"]}}`)
	var stdout strings.Builder
	err := run(context.Background(),
		[]string{"--format", "json", "--dry-run", "merge", "--base", base, "--add", add, "--out", out},
		func(string) string { return "" }, nil, "", &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("merge --dry-run wrote %s (%v)", out, statErr)
	}
	var res result
	if jsonErr := json.Unmarshal([]byte(stdout.String()), &res); jsonErr != nil || !res.DryRun || res.Diff == "" {
		t.Errorf("envelope = %+v (%v), want dry_run with a diff", res, jsonErr)
	}
}

type uploadServer struct {
	mu       sync.Mutex
	requests []string
}

func (s *uploadServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	s.mu.Unlock()
	_, _ = io.Copy(io.Discard, r.Body)
	if r.Method == http.MethodGet {
		w.Header().Set("ETag", `"etag-1"`)
		_, _ = io.WriteString(w, `{"grants": []}`)
		return
	}
	w.Header().Set("ETag", `"etag-2"`)
}

func (s *uploadServer) applied() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, request := range s.requests {
		if strings.HasSuffix(request, "/acl") && strings.HasPrefix(request, "POST") {
			return true
		}
	}
	return false
}

func runUploadAgainst(t *testing.T, server *httptest.Server, path string, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr strings.Builder
	err := run(context.Background(), append([]string{"--file", path}, args...),
		func(key string) string {
			return map[string]string{"TAILSCALE_API_KEY": "token", "TAILSCALE_TAILNET": "example.com"}[key]
		},
		server.Client(), server.URL, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func TestJSONUploadRequiresApprovalAndSendsNothing(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)
	api := &uploadServer{}
	server := httptest.NewServer(http.HandlerFunc(api.handler))
	defer server.Close()

	_, stderr, err := runUploadAgainst(t, server, path, "--format", "json", "upload", "--accept-remote-changes")
	if exitCode(err) != exitUsage {
		t.Fatalf("exit = %d (%v), want %d", exitCode(err), err, exitUsage)
	}
	if line := decodeAxError(t, stderr); line.ErrorCode != "confirmation_required" {
		t.Errorf("error_code = %q, want confirmation_required", line.ErrorCode)
	}
	if len(api.requests) != 0 {
		t.Errorf("requests = %v, want none before approval", api.requests)
	}
}

func TestUploadDryRunValidatesWithoutApplying(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)
	api := &uploadServer{}
	server := httptest.NewServer(http.HandlerFunc(api.handler))
	defer server.Close()

	stdout, _, err := runUploadAgainst(
		t,
		server,
		path,
		"--format",
		"json",
		"--dry-run",
		"--if-match",
		`"etag-1"`,
		"upload",
	)
	if err != nil {
		t.Fatalf("dry-run upload = %v", err)
	}
	var res result
	if jsonErr := json.Unmarshal([]byte(stdout), &res); jsonErr != nil || !res.DryRun {
		t.Errorf("envelope = %+v (%v), want dry_run", res, jsonErr)
	}
	if api.applied() {
		t.Errorf("requests = %v, want no apply", api.requests)
	}
	if _, statErr := os.Stat(observedstate.Path(path)); !os.IsNotExist(statErr) {
		t.Errorf("dry-run upload wrote state (%v)", statErr)
	}

	_, _, err = runUploadAgainst(t, server, path, "--dry-run", "--if-match", `"stale"`, "upload")
	if err == nil || !strings.Contains(err.Error(), "upload refused") {
		t.Errorf("stale dry-run upload = %v, want the stale-ETag refusal", err)
	}
}

func TestDryRunPullAndPlanWriteNothing(t *testing.T) {
	t.Parallel()
	api := &uploadServer{}
	server := httptest.NewServer(http.HandlerFunc(api.handler))
	defer server.Close()

	pulled := filepath.Join(t.TempDir(), "acl.hujson")
	stdout, _, err := runUploadAgainst(t, server, pulled, "--format", "json", "--dry-run", "pull")
	if err != nil {
		t.Fatalf("pull --dry-run = %v", err)
	}
	assertDryRunEnvelope(t, stdout, pulled, true)
	for _, path := range []string{pulled, observedstate.Path(pulled)} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("pull --dry-run wrote %s (%v)", path, statErr)
		}
	}

	planned := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, planned, `{"grants": []}`)
	if _, _, err = runUploadAgainst(t, server, planned, "--format", "json", "--dry-run", "plan"); err != nil {
		t.Fatalf("plan --dry-run = %v", err)
	}
	if _, statErr := os.Stat(observedstate.Path(planned)); !os.IsNotExist(statErr) {
		t.Errorf("plan --dry-run recorded state (%v)", statErr)
	}
}
