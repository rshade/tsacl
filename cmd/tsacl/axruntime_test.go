package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/ax-go"

	"github.com/rshade/tsacl/internal/tailapi"
	"github.com/rshade/tsacl/pkg/policycore"
	"github.com/rshade/tsacl/pkg/policycore/errcode"
)

type axErrorLine struct {
	ErrorCode         string `json:"error_code"`
	Message           string `json:"message"`
	TraceID           string `json:"trace_id"`
	Tool              string `json:"tool"`
	Version           string `json:"version"`
	Retryable         *bool  `json:"retryable"`
	RetryAfterSeconds int64  `json:"retry_after_seconds"`
}

// decodeAxError requires stderr to hold exactly one ax.Error JSON line.
func decodeAxError(t *testing.T, stderr string) axErrorLine {
	t.Helper()
	trimmed := strings.TrimSuffix(stderr, "\n")
	if trimmed == "" || strings.Contains(trimmed, "\n") {
		t.Fatalf("stderr = %q, want exactly one JSON error line", stderr)
	}
	var line axErrorLine
	if err := json.Unmarshal([]byte(trimmed), &line); err != nil {
		t.Fatalf("stderr is not an ax.Error line: %v\n%s", err, stderr)
	}
	if line.Tool != toolName || line.ErrorCode == "" {
		t.Errorf("ax.Error = %+v, want tool %q and a non-empty error_code", line, toolName)
	}
	return line
}

// assertVerdictStderr requires silence after a success and a single ax.Error
// line after any failure.
func assertVerdictStderr(t *testing.T, stderr string, err error) {
	t.Helper()
	if err == nil {
		if stderr != "" {
			t.Errorf("stderr = %q, want quiet", stderr)
		}
		return
	}
	decodeAxError(t, stderr)
}

func TestAxErrorForClassifiesErrors(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name      string
		err       error
		wantCode  string
		wantExit  int
		retryable bool
		retryIn   int64
	}{
		{"usage", usagef("bad"), errCodeValidation, exitUsage, false, 0},
		{"interrupted", context.Canceled, errCodeInterrupted, exitUsage, false, 0},
		{"indeterminate", errReachabilityIndeterminate, errCodeIndeterminate, exitIndeterminate, false, 0},
		{"failure", errors.New("assertions failed"), errCodeFailed, exitFailed, false, 0},
		{
			"unavailable",
			&tailapi.ValidationUnavailableError{Status: 503, Message: "down"},
			errCodeUnavailable, exitUsage, false, 0,
		},
		{
			"rate limited",
			&tailapi.ValidationUnavailableError{Status: 429, Message: "slow", RetryAfter: "30"},
			errCodeRateLimited, exitUsage, true, 30,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got := axErrorFor(context.Background(), testCase.err)
			if got.ErrorCode != testCase.wantCode || got.ExitCode() != testCase.wantExit ||
				(got.Retryable != nil && *got.Retryable) != testCase.retryable || got.RetryAfterSeconds != testCase.retryIn {
				t.Errorf("axErrorFor = %+v (exit %d), want code %q exit %d retryable %v retry %d",
					got, got.ExitCode(), testCase.wantCode, testCase.wantExit, testCase.retryable, testCase.retryIn)
			}
		})
	}
}

func TestAxErrorForKeepsATopLevelEnvelope(t *testing.T) {
	t.Parallel()
	top := ax.NewError(context.Background(), "confirmation_required", "confirm with --yes",
		ax.WithErrorExitCode(exitUsage))
	if got := axErrorFor(context.Background(), top); got != top {
		t.Errorf("axErrorFor rebuilt a top-level envelope: %+v", got)
	}
}

func TestAxErrorForAdoptsANestedLibraryError(t *testing.T) {
	t.Parallel()
	_, rosterErr := policycore.ParseRoster([]byte(`{"Ada@example.com": "admin", "ada@example.com": "member"}`))
	err := usagef("could not load --roster r.json: %w", rosterErr)

	got := axErrorFor(context.Background(), err, ax.WithErrorContext(map[string]any{"verdict": "x"}))

	if got.ErrorCode != errcode.RosterEntryInvalid {
		t.Errorf("ErrorCode = %q, want %q", got.ErrorCode, errcode.RosterEntryInvalid)
	}
	if got.Message != err.Error() || !strings.HasPrefix(got.Message, "could not load --roster r.json: roster:") {
		t.Errorf("Message = %q, want the full top-level text %q", got.Message, err.Error())
	}
	if got.Tool != toolName || got.ExitCode() != exitUsage {
		t.Errorf("tool %q exit %d, want %q and %d", got.Tool, got.ExitCode(), toolName, exitUsage)
	}
	if got.ActionableFix != errcode.Fix(errcode.RosterEntryInvalid) {
		t.Errorf("ActionableFix = %q, want the library fix", got.ActionableFix)
	}
	if got.Retryable == nil || *got.Retryable {
		t.Errorf("Retryable = %v, want an explicit false", got.Retryable)
	}
	if got.Context["verdict"] != "x" {
		t.Errorf("Context = %v, want the caller's extra options applied", got.Context)
	}
}

func TestAxErrorForDoesNotCopyNestedContextOrSuggestions(t *testing.T) {
	t.Parallel()
	nested := ax.NewError(context.Background(), errCodeValidation, "secret ada@example.com",
		ax.WithErrorContext(map[string]any{"login": "ada@example.com"}),
		ax.WithSuggestions("email ada@example.com"))
	got := axErrorFor(context.Background(), fmt.Errorf("scrubbed: %w", nested))
	if got.Message != "scrubbed: secret ada@example.com" {
		t.Errorf("Message = %q, want the top-level text", got.Message)
	}
	if len(got.Context) != 0 || len(got.Suggestions) != 0 {
		t.Errorf("Context = %v, Suggestions = %v, want neither copied", got.Context, got.Suggestions)
	}
}

func TestExitCodePrecedenceOverLibraryErrors(t *testing.T) {
	t.Parallel()
	_, libraryErr := policycore.ResolveIPSet("ipset:missing", nil)
	testCases := []struct {
		name string
		err  error
		want int
	}{
		{"a lone library error exits 2", libraryErr, exitUsage},
		{"a wrapped library error exits 2", fmt.Errorf("could not resolve: %w", libraryErr), exitUsage},
		{"indeterminate wins over a library error",
			fmt.Errorf("%w: %w", errReachabilityIndeterminate, libraryErr), exitIndeterminate},
		{"a runtime exit status wins over a library error",
			fmt.Errorf("%w: %w", exitStatusError{code: 3}, libraryErr), 3},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := exitCode(testCase.err); got != testCase.want {
				t.Errorf("exitCode = %d, want %d", got, testCase.want)
			}
		})
	}
}

func TestUsageFailuresWriteOneEnvelopeAndExitTwo(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"bogus"},
		{"--bogus", "check"},
		{"lint", "--bogus"},
		{"lint", "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			err := run(context.Background(), args, func(string) string { return "" }, nil, "", &stdout, &stderr)
			if code := exitCode(err); code != exitUsage {
				t.Errorf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
			if line := decodeAxError(t, stderr.String()); line.ErrorCode != errCodeValidation {
				t.Errorf("error_code = %q, want %q", line.ErrorCode, errCodeValidation)
			}
		})
	}
}

func TestSingleDashAgentFlagsAreAccepted(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	err := run(context.Background(),
		[]string{"-file", path, "-dry-run", "-yes", "-idempotency-key", "k", "lint"},
		func(string) string { return "" }, nil, "", &stdout, &stderr)
	if err != nil {
		t.Fatalf("run = %v, stderr %q", err, stderr.String())
	}
}

func runLintWithEnv(t *testing.T, env map[string]string, extra ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	args := append([]string{"--file", path}, extra...)
	args = append(args, "lint")
	err := run(context.Background(), args, func(key string) string { return env[key] }, nil, "", &stdout, &stderr)
	if err != nil {
		t.Fatalf("run = %v, stderr %q", err, stderr.String())
	}
	return stdout.String()
}

func TestOutputModeResolution(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		env      map[string]string
		args     []string
		wantJSON bool
	}{
		{"default is human", nil, nil, false},
		{"agent mode selects json", map[string]string{"AGENT_MODE": "1"}, nil, true},
		{"flag beats agent mode", map[string]string{"AGENT_MODE": "1"}, []string{"--format", "human"}, false},
		{"flag selects json", nil, []string{"--format", "json"}, true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			stdout := runLintWithEnv(t, testCase.env, testCase.args...)
			if got := strings.HasPrefix(strings.TrimSpace(stdout), "{"); got != testCase.wantJSON {
				t.Errorf("json = %v, want %v; stdout %q", got, testCase.wantJSON, stdout)
			}
		})
	}
}

func TestJSONEnvelopeCarriesOnlyAdditiveMeta(t *testing.T) {
	t.Parallel()
	stdout := runLintWithEnv(t, nil, "--format", "json")
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	var meta struct {
		TraceID string `json:"trace_id"`
	}
	if err := json.Unmarshal(envelope["meta"], &meta); err != nil || meta.TraceID == "" {
		t.Fatalf("meta = %s, want a trace_id (%v)", envelope["meta"], err)
	}
	if string(envelope["schema_version"]) != `"`+schemaVersion+`"` {
		t.Errorf("schema_version = %s, want %q", envelope["schema_version"], schemaVersion)
	}
}
