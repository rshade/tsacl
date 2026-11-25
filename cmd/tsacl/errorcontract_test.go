package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/hujsonedit"
)

// collidingRosterArgs writes a valid policy and a roster whose two logins
// collide after lowercasing, then returns the global arguments for check.
func collidingRosterArgs(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.hujson")
	roster := filepath.Join(dir, "roster.json")
	files := map[string]string{
		policy: `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`,
		roster: `{"Ada@example.com": "admin", "ada@example.com": "member"}`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"--file", policy, "--roster", roster}
}

func TestRosterRejectionCarriesTheLibraryCode(t *testing.T) {
	t.Parallel()
	args := append(collidingRosterArgs(t), "check", "--src", "ada@example.com", "--dst", "10.0.0.1:22")

	var stdout, stderr strings.Builder
	err := run(context.Background(), args, func(string) string { return "" }, nil, "", &stdout, &stderr)

	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	line := decodeAxError(t, stderr.String())
	if line.ErrorCode != errcode.RosterEntryInvalid {
		t.Errorf("error_code = %q, want %q", line.ErrorCode, errcode.RosterEntryInvalid)
	}
	if !strings.HasPrefix(line.Message, "could not load --roster ") {
		t.Errorf("message = %q, want tsacl's prefix kept", line.Message)
	}
}

func TestSanitizedRosterRejectionLeaksNoLogin(t *testing.T) {
	t.Parallel()
	args := append([]string{"--sanitize", "identity"}, collidingRosterArgs(t)...)
	args = append(args, "check", "--src", "ada@example.com", "--dst", "10.0.0.1:22", "--format", "json")

	var stdout, stderr strings.Builder
	err := run(context.Background(), args, func(string) string { return "" }, nil, "", &stdout, &stderr)

	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	line := decodeAxError(t, stderr.String())
	if line.ErrorCode != errcode.RosterEntryInvalid {
		t.Errorf("error_code = %q, want %q", line.ErrorCode, errcode.RosterEntryInvalid)
	}
	for _, stream := range []string{stdout.String(), stderr.String()} {
		if strings.Contains(strings.ToLower(stream), "ada@example.com") {
			t.Errorf("output leaks the login:\n%s", stream)
		}
	}
}

const lintablePolicy = `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}` + "\n"

const malformedPolicy = `{"grants": [,}` + "\n"

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// paddedPolicy is lintablePolicy grown to exactly size bytes with HuJSON
// comment lines, so the file stays a valid policy at any size.
func paddedPolicy(size int) string {
	const line = "// padding padding padding padding padding padding padding padding padding\n"
	var padded strings.Builder
	for padded.Len()+len(line)+len(lintablePolicy) <= size {
		padded.WriteString(line)
	}
	padded.WriteString("//" + strings.Repeat("p", size-padded.Len()-len(lintablePolicy)-len("//\n")) + "\n")
	padded.WriteString(lintablePolicy)
	return padded.String()
}

type cliOutcome struct {
	stdout, stderr string
	code           int
}

func runCLI(t *testing.T, args ...string) cliOutcome {
	t.Helper()
	return runCLIAgainst(t, nil, args...)
}

// runCLIAgainst runs tsacl with credentials for example.com pointed at server,
// or with no credentials and no control plane when server is nil.
func runCLIAgainst(t *testing.T, server *httptest.Server, args ...string) cliOutcome {
	t.Helper()
	getenv := func(string) string { return "" }
	var client *http.Client
	var apiURL string
	if server != nil {
		getenv = func(key string) string {
			return map[string]string{"TAILSCALE_API_KEY": "token", "TAILSCALE_TAILNET": "example.com"}[key]
		}
		client, apiURL = server.Client(), server.URL
	}
	var stdout, stderr strings.Builder
	err := run(context.Background(), args, getenv, client, apiURL, &stdout, &stderr)
	return cliOutcome{stdout: stdout.String(), stderr: stderr.String(), code: exitCode(err)}
}

// envelope decodes the error envelope, which is stderr's last line: an
// effectful command logs ax-go's Perform lines ahead of it.
func (o cliOutcome) envelope(t *testing.T) axErrorLine {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(o.stderr, "\n"), "\n")
	return decodeAxError(t, lines[len(lines)-1]+"\n")
}

func assertCLIError(t *testing.T, got cliOutcome, code string) {
	t.Helper()
	if got.code != exitUsage {
		t.Errorf("exit code = %d, want %d", got.code, exitUsage)
	}
	if line := got.envelope(t); line.ErrorCode != code {
		t.Errorf("error_code = %q, want %q (message %q)", line.ErrorCode, code, line.Message)
	}
}

func invalidIPSetMember(t *testing.T) cliOutcome {
	t.Helper()
	policy := writeTestFile(t, t.TempDir(), "policy.hujson", lintablePolicy)
	return runCLI(t, "--file", policy, "ipset", "add", "--name", "ipset:a", "--member", "bogus")
}

func TestInvalidIPSetMemberCarriesTheLibraryCode(t *testing.T) {
	t.Parallel()
	assertCLIError(t, invalidIPSetMember(t), errcode.IPSetMemberInvalid)
}

// The library builds its errors without a run in scope, and this one reaches
// ax.Execute unwrapped, so the trace ID, tool, and version must be stamped by
// the run rather than left zero.
func TestLibraryErrorEnvelopeIsStampedByTheRun(t *testing.T) {
	t.Parallel()
	got := invalidIPSetMember(t).envelope(t)
	if !strings.HasPrefix(got.Message, "ipset member ") {
		t.Fatalf("message = %q, want the library's own text, unwrapped", got.Message)
	}
	if strings.Trim(got.TraceID, "0") == "" {
		t.Errorf("trace_id = %q, want a live trace ID", got.TraceID)
	}
	if got.Tool != toolName {
		t.Errorf("tool = %q, want %q", got.Tool, toolName)
	}
	if got.Version == "" {
		t.Error("version is empty")
	}
}

func TestMaxPolicyBytesOutOfRangeFailsBeforeAnyRead(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "never-read.hujson")
	for _, limit := range []string{"0", "-1", "1073741825"} {
		t.Run(limit, func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, "--file", missing, "--max-policy-bytes="+limit, "lint")
			// A missing --file would fail differently, so this code proves the
			// limit was rejected before the policy was opened.
			assertCLIError(t, got, errcode.ConfigMaxBytesInvalid)
		})
	}
}

// overDefaultLimit is one byte past the default --max-policy-bytes, and
// raisedLimit is a --max-policy-bytes value that admits it.
const (
	overDefaultLimit = int(hujsonedit.DefaultMaxBytes) + 1
	raisedLimit      = 2 * hujsonedit.DefaultMaxBytes
)

// A production policy of several megabytes must lint with no flag at all.
func TestMultiMegabytePolicyNeedsNoFlag(t *testing.T) {
	t.Parallel()
	const nineMB = 9_000_000
	policy := writeTestFile(t, t.TempDir(), "large.hujson", paddedPolicy(nineMB))
	got := runCLI(t, "--file", policy, "lint", "--format", "json")
	if got.code == exitUsage || got.stdout == "" {
		t.Errorf("lint of a %d-byte policy exited %d with stdout %q; stderr %s",
			nineMB, got.code, got.stdout, got.stderr)
	}
}

func TestOversizePolicyIsRejectedUnlessTheLimitIsRaised(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := paddedPolicy(overDefaultLimit)
	if len(content) != overDefaultLimit {
		t.Fatalf("padded policy is %d bytes, want %d", len(content), overDefaultLimit)
	}
	big := writeTestFile(t, dir, "big.hujson", content)

	rejected := runCLI(t, "--file", big, "lint", "--format", "json")
	assertCLIError(t, rejected, errcode.ConfigTooLarge)
	if rejected.stdout != "" {
		t.Errorf("stdout = %q, want nothing for a rejected read", rejected.stdout)
	}

	limit := strconv.FormatInt(raisedLimit, 10)
	raised := runCLI(t, "--file", big, "--max-policy-bytes", limit, "lint", "--format", "json")
	if raised.code == exitUsage || raised.stdout == "" {
		t.Errorf("lint with a raised limit exited %d with stdout %q; stderr %s",
			raised.code, raised.stdout, raised.stderr)
	}
}

// TestControlPlaneCommandsHonorTheRaisedLimit covers the commands whose --file
// read happens inside tailapi rather than in a command runner. The fake
// control plane serves the candidate as the deployed policy, so plan proves the
// read without also paying for a diff of every line.
func TestControlPlaneCommandsHonorTheRaisedLimit(t *testing.T) {
	t.Parallel()
	content := paddedPolicy(overDefaultLimit)
	big := writeTestFile(t, t.TempDir(), "big.hujson", content)
	limit := strconv.FormatInt(raisedLimit, 10)
	commands := map[string][]string{
		"validate":                 {"validate"},
		"plan":                     {"plan"},
		"upload":                   {"--if-match", `"etag"`, "upload"},
		"upload --dry-run":         {"--if-match", `"etag"`, "upload", "--dry-run"},
		"lint --online-validation": {"lint", "--online-validation"},
	}
	for name, command := range commands {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// submissions counts the requests that carry the policy: validate for
			// every command but upload, which sends it to the policy endpoint.
			var submissions atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("ETag", `"etag"`)
				if r.Method == http.MethodGet {
					_, _ = io.WriteString(w, content)
					return
				}
				submissions.Add(1)
			}))
			defer server.Close()

			rejected := runCLIAgainst(t, server, append([]string{"--file", big}, command...)...)
			assertCLIError(t, rejected, errcode.ConfigTooLarge)
			if got := submissions.Load(); got != 0 {
				t.Fatalf("default limit submitted the policy %d times, want 0", got)
			}

			raised := append([]string{"--file", big, "--max-policy-bytes", limit}, command...)
			if accepted := runCLIAgainst(t, server, raised...); accepted.code == exitUsage {
				t.Errorf("raised limit exited %d; stderr %s", accepted.code, accepted.stderr)
			}
			if got := submissions.Load(); got != 1 {
				t.Errorf("raised limit submitted the policy %d times, want 1", got)
			}
		})
	}
}

func TestMalformedPolicyExitsTwoOnEveryCommand(t *testing.T) {
	t.Parallel()
	for name, args := range map[string]func(dir string) []string{
		"ipset add": func(dir string) []string {
			return []string{"--file", writeTestFile(t, dir, "bad.hujson", malformedPolicy),
				"ipset", "add", "--name", "ipset:a", "--member", "10.0.0.1"}
		},
		"merge": func(dir string) []string {
			return []string{"merge", "--base", writeTestFile(t, dir, "bad.hujson", malformedPolicy),
				"--add", writeTestFile(t, dir, "ok.hujson", lintablePolicy)}
		},
		"lint": func(dir string) []string {
			return []string{"--file", writeTestFile(t, dir, "bad.hujson", malformedPolicy), "lint"}
		},
		"jq": func(dir string) []string {
			return []string{"--file", writeTestFile(t, dir, "bad.hujson", malformedPolicy), "jq", "."}
		},
		"normalize": func(dir string) []string {
			return []string{"--file", writeTestFile(t, dir, "bad.hujson", malformedPolicy), "normalize"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := runCLI(t, args(t.TempDir())...)
			assertCLIError(t, got, errcode.ConfigInvalid)
			if line := got.envelope(t); !strings.Contains(line.Message, "line 1, column 13") {
				t.Errorf("message %q lost hujson's position detail", line.Message)
			}
		})
	}
}
