package integration_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/rshade/tsacl/internal/aclpolicy"
	"github.com/rshade/tsacl/internal/observedstate"
)

const (
	testTailnet = "example.com"
	testAPIKey  = "tskey-api-integration-test"
)

func TestTSACLPlanValidateApplyRestoreWorkflow(t *testing.T) {
	t.Parallel()
	const originalPolicy = `// integration-test base policy
{
	"grants": [
		{"src": ["*"], "dst": ["*"], "ip": ["*"]},
	],
}
`
	const goodPolicy = `// integration-test base policy
// harmless workflow verification comment
{
	"grants": [
		{"src": ["*"], "dst": ["*"], "ip": ["*"]},
	],
}
`
	const badPolicy = `{
	"grants": [
		{"src": ["*"], "dst": ["*"], "ip": ["tcp:not-a-port"]},
	],
}
`

	tempDir := t.TempDir()
	originalPath := filepath.Join(tempDir, "original.hujson")
	goodPath := writePolicy(t, tempDir, "good.hujson", goodPolicy)
	badPath := writePolicy(t, tempDir, "bad.hujson", badPolicy)
	binary := buildTSACL(t, tempDir)

	api := newPolicyAPIServer(t, originalPolicy)
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	runner := cliRunner{
		binary: binary,
		env: []string{
			"TAILSCALE_API_KEY=" + testAPIKey,
			"TAILSCALE_TAILNET=" + testTailnet,
			"TAILSCALE_API_URL=" + server.URL,
		},
	}

	originalETag := policyETag(originalPolicy)
	pullJSON := runner.mustSucceed(t, "-format", "json", "--file", originalPath, "pull")
	var pulled struct {
		File    string `json:"file"`
		Tailnet string `json:"tailnet"`
		ETag    string `json:"etag"`
	}
	if err := json.Unmarshal([]byte(pullJSON), &pulled); err != nil {
		t.Fatalf("decode pull result: %v\n%s", err, pullJSON)
	}
	if pulled.File != originalPath || pulled.Tailnet != testTailnet || pulled.ETag != originalETag {
		t.Errorf("pull envelope = %#v", pulled)
	}
	if recorded, readErr := observedstate.Read(originalPath, testTailnet); readErr != nil || recorded != originalETag {
		t.Errorf("recorded pull ETag = %q, %v; want %q", recorded, readErr, originalETag)
	}
	pulledPolicy, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(pulledPolicy) != originalPolicy {
		t.Errorf("pulled policy changed bytes:\ngot:\n%s\nwant:\n%s", pulledPolicy, originalPolicy)
	}
	output := runner.mustFail(t, "--file", originalPath, "pull")
	assertContains(t, output, "refusing to overwrite", "--force")
	output = runner.mustSucceed(t, "--file", originalPath, "pull", "--force")
	assertContains(t, output, "pulled deployed policy", "ETag "+originalETag)

	output = runner.mustSucceed(t, "--file", originalPath, "plan")
	assertContains(t, output, "plan valid; no changes", "ETag "+originalETag)

	output = runner.mustFail(t, "--file", badPath, "plan")
	assertContains(t, output, "ACL validation failed", "not-a-port")
	api.assertPolicy(t, originalPolicy)

	output = runner.mustFail(t, "--file", badPath, "--if-match", trimETag(originalETag), "upload")
	assertContains(t, output, "not-a-port", "(400)")
	api.assertPolicy(t, originalPolicy)

	output = runner.mustSucceed(t, "--file", goodPath, "plan")
	assertContains(t, output,
		"--- deployed",
		"+++ "+goodPath,
		"+// harmless workflow verification comment",
		"plan valid; changes found",
		"ETag "+originalETag,
	)

	output = runner.mustSucceed(t, "--file", goodPath, "upload")
	assertContains(t, output, "uploaded "+goodPath)
	api.assertPolicy(t, goodPolicy)

	goodETag := policyETag(goodPolicy)
	if recorded, readErr := observedstate.Read(goodPath, testTailnet); readErr != nil || recorded != goodETag {
		t.Errorf("recorded upload ETag = %q, %v; want %q", recorded, readErr, goodETag)
	}
	output = runner.mustSucceed(t, "--file", goodPath, "plan")
	assertContains(t, output, "plan valid; no changes", "ETag "+goodETag)

	output = runner.mustFail(t, "--file", originalPath, "--if-match", trimETag(originalETag), "upload")
	assertContains(t, output, "upload refused", "tsacl --file <remote-policy.hujson> pull", "tsacl merge --base")
	api.assertPolicy(t, goodPolicy)

	output = runner.mustSucceed(t, "--file", originalPath, "--if-match", trimETag(goodETag), "upload")
	assertContains(t, output, "uploaded "+originalPath)
	api.assertPolicy(t, originalPolicy)

	output = runner.mustSucceed(t, "--file", originalPath, "plan")
	assertContains(t, output, "plan valid; no changes", "ETag "+originalETag)
	api.assertRequestCounts(t, 5, 1, 1, 2)
}

func TestTSACLValidationWarningClassification(t *testing.T) {
	t.Parallel()
	runner, api := newValidationRunner(t)

	// Warnings with no errors and no message are a success: the policy is
	// valid, every warning is reported, and the exit code stays 0.
	warningStdout, warningStderr, err := runner.runSplit(t,
		"-format", "json", "--file", "testdata/validation_warning.hujson", "validate")
	if err != nil {
		t.Fatalf("warnings-only validation failed: %v\nstdout:\n%s\nstderr:\n%s", err, warningStdout, warningStderr)
	}
	wantGolden, err := os.ReadFile("testdata/validation_warning.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if stripMeta(warningStdout) != string(wantGolden) {
		t.Errorf("warnings JSON differs from golden:\ngot:\n%s\nwant:\n%s", warningStdout, wantGolden)
	}
	assertContains(t, warningStderr, "ACL validation warning", "group is not syncing from SCIM")

	planWarningStdout, planWarningStderr, err := runner.runSplit(t,
		"-format", "json", "--file", "testdata/validation_warning.hujson", "plan")
	if err != nil {
		t.Fatalf("warnings-only plan failed: %v\nstdout:\n%s\nstderr:\n%s",
			err, planWarningStdout, planWarningStderr)
	}
	warningPlanResult := decodeEnvelope(t, planWarningStdout, "warnings-only plan")
	if len(warningPlanResult.Validation.Warnings) != 1 {
		t.Errorf("warnings-only plan envelope = %#v", warningPlanResult)
	}
	assertContains(t, planWarningStderr, "ACL validation warning", "group is not syncing from SCIM")

	// A message alongside warnings is not proof the policy is clean. The
	// warnings channel was never captured from the live control plane, so the
	// CLI reports indeterminate rather than guessing in either direction.
	messagePath := writePolicy(t, t.TempDir(), "warning-message.hujson", `{
		"validation-scenario": "warnings-with-message",
		"grants": [],
	}`)
	messageStdout, messageStderr, err := runner.runSplit(t, "-format", "json", "--file", messagePath, "validate")
	if code := exitCodeOf(t, err); code != 10 {
		t.Errorf("warnings-with-message exit = %d, want 10\nstdout:\n%s\nstderr:\n%s",
			code, messageStdout, messageStderr)
	}
	messageResult := decodeEnvelope(t, messageStdout, "warnings-with-message")
	if messageResult.Status != "indeterminate" || messageResult.Validation.Message != "warning(s) found" ||
		len(messageResult.Validation.Warnings) != 1 || len(messageResult.Validation.Failures) != 0 {
		t.Errorf("warnings-with-message envelope = %#v", messageResult)
	}

	// plan advertises exit 10 in --help and -schema too, so its half of that
	// contract is asserted rather than inferred from validate's.
	planMessageStdout, planMessageStderr, err := runner.runSplit(t,
		"-format", "json", "--file", messagePath, "plan")
	if code := exitCodeOf(t, err); code != 10 {
		t.Errorf("warnings-with-message plan exit = %d, want 10\nstdout:\n%s\nstderr:\n%s",
			code, planMessageStdout, planMessageStderr)
	}
	planMessageResult := decodeEnvelope(t, planMessageStdout, "warnings-with-message plan")
	// changed must stay absent: a candidate that was never diffed has no answer,
	// and reporting one would read as a confident "no changes".
	if planMessageResult.Status != "indeterminate" || planMessageResult.Diff != "" ||
		planMessageResult.Changed != nil || planMessageResult.Validation.Message != "warning(s) found" ||
		len(planMessageResult.Validation.Warnings) != 1 {
		t.Errorf("warnings-with-message plan envelope = %#v", planMessageResult)
	}
	api.assertRequestCounts(t, 4, 0, 0, 0)
}

func TestTSACLValidationFailureClassification(t *testing.T) {
	t.Parallel()
	runner, api := newValidationRunner(t)

	dataOnlyPath := writePolicy(t, t.TempDir(), "data-only.hujson", `{
		"validation-scenario": "data-only",
		"grants": [],
	}`)
	dataStdout, dataStderr, err := runner.runSplit(t, "-format", "json", "--file", dataOnlyPath, "validate")
	if code := exitCodeOf(t, err); code != 1 {
		t.Errorf("data-only validate exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, dataStdout, dataStderr)
	}
	dataResult := decodeEnvelope(t, dataStdout, "data-only")
	if dataResult.Status != "failed" || len(dataResult.Validation.Failures) != 1 ||
		dataResult.Validation.Failures[0].User != "data-only-user" ||
		len(dataResult.Validation.Failures[0].Errors) != 1 {
		t.Errorf("data-only envelope = %#v", dataResult)
	}
	assertContains(t, dataStderr, "ACL validation failed", "data-only failure")

	planStdout, planStderr, err := runner.runSplit(t, "-format", "json", "--file", dataOnlyPath, "plan")
	if code := exitCodeOf(t, err); code != 1 {
		t.Errorf("data-only plan exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, planStdout, planStderr)
	}
	planResult := decodeEnvelope(t, planStdout, "data-only plan")
	if planResult.Status != "failed" || planResult.Diff != "" || len(planResult.Validation.Failures) != 1 {
		t.Errorf("data-only plan envelope = %#v", planResult)
	}

	// A control plane that never judged the policy is a collection failure, not
	// a verdict: exit 2, and stdout stays empty rather than calling a policy the
	// server never read invalid.
	unavailablePath := writePolicy(t, t.TempDir(), "unavailable.hujson", `{
		"validation-scenario": "unavailable",
		"grants": [],
	}`)
	unavailableStdout, unavailableStderr, err := runner.runSplit(t,
		"-format", "json", "--file", unavailablePath, "validate")
	if code := exitCodeOf(t, err); code != 2 {
		t.Errorf("unavailable validate exit = %d, want 2\nstdout:\n%s\nstderr:\n%s",
			code, unavailableStdout, unavailableStderr)
	}
	if unavailableStdout != "" {
		t.Errorf("unavailable validate printed a verdict on stdout:\n%s", unavailableStdout)
	}
	assertContains(t, unavailableStderr, "ACL validation unavailable", "backend unavailable")
	api.assertRequestCounts(t, 3, 0, 0, 0)
}

// validationEnvelope is the subset of the result envelope these tests assert
// on. One shared type rather than an anonymous struct per decode: a renamed
// JSON key then fails every test at once instead of silently decoding to a zero
// value in the copies that were missed.
type validationEnvelope struct {
	Status     string `json:"status"`
	Diff       string `json:"diff"`
	Changed    *bool  `json:"changed"`
	Validation struct {
		Message  string `json:"message"`
		Failures []struct {
			User   string   `json:"user"`
			Errors []string `json:"errors"`
		} `json:"failures"`
		Warnings []json.RawMessage `json:"warnings"`
	} `json:"validation"`
}

func decodeEnvelope(t *testing.T, stdout, label string) validationEnvelope {
	t.Helper()
	var envelope validationEnvelope
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("%s stdout is not JSON: %v\n%s", label, err, stdout)
	}
	return envelope
}

func newValidationRunner(t *testing.T) (cliRunner, *policyAPIServer) {
	t.Helper()
	api := newPolicyAPIServer(t, `{"grants": []}`)
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	return cliRunner{
		binary: buildTSACL(t, t.TempDir()),
		env: []string{
			"TAILSCALE_API_KEY=" + testAPIKey,
			"TAILSCALE_TAILNET=" + testTailnet,
			"TAILSCALE_API_URL=" + server.URL,
		},
	}, api
}

// exitCodeOf reports the CLI's exit status. The exit-code scheme is the
// contract shell callers branch on, so a test asserts the number rather than
// only that the command failed.
func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("command failed without an exit status: %v", err)
	}
	return exitErr.ExitCode()
}

func TestTSACLTypedEditPreservesSSHExtensions(t *testing.T) {
	t.Parallel()
	const originalPolicy = `{
	"ssh": [{
		"action": "accept",
		"src": ["autogroup:member"],
		"dst": ["tag:web"],
		"users": ["ubuntu"],
		"acceptEnv": ["LANG", "LC_*"]
	}],
	"sshTests": [{
		"src": "alice@example.com",
		"dst": ["tag:web"],
		"accept": ["ubuntu"],
		"check": ["root"],
		"deny": ["guest"],
		"srcPostureAttrs": {"node:os": "linux"}
	}]
}`

	tempDir := t.TempDir()
	path := writePolicy(t, tempDir, "acl.json", originalPolicy)
	runner := cliRunner{binary: buildTSACL(t, tempDir)}
	runner.mustSucceed(
		t,
		"--file", path,
		"grant", "add",
		"--src", "autogroup:member",
		"--dst", "tag:web",
		"--ip", "tcp:443",
	)

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("Grants = %#v, want the authored grant", policy.Grants)
	}
	if len(policy.SSH) != 1 || len(policy.SSH[0].AcceptEnv) != 2 {
		t.Errorf("SSH = %#v, want acceptEnv preserved", policy.SSH)
	}
	if len(policy.SSHTests) != 1 ||
		len(policy.SSHTests[0].Accept) != 1 ||
		len(policy.SSHTests[0].Check) != 1 ||
		len(policy.SSHTests[0].Deny) != 1 ||
		policy.SSHTests[0].SrcPostureAttrs["node:os"] != "linux" {
		t.Errorf("SSHTests = %#v, want every assertion field preserved", policy.SSHTests)
	}
}

type cliRunner struct {
	binary string
	env    []string
}

func (r cliRunner) mustSucceed(t *testing.T, args ...string) string {
	t.Helper()
	output, err := r.run(t, args...)
	if err != nil {
		t.Fatalf("tsacl %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

func (r cliRunner) mustFail(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr, err := r.runSplit(t, args...)
	if err == nil {
		t.Fatalf("tsacl %s unexpectedly succeeded:\n%s%s", strings.Join(args, " "), stdout, stderr)
	}
	return stdout + decodeErrorEnvelope(stderr)
}

func decodeErrorEnvelope(stderr string) string {
	var envelope struct {
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(stderr)), &envelope) != nil || envelope.Message == "" {
		return stderr
	}
	return "tsacl: " + envelope.Message + "\n"
}

func (r cliRunner) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), r.binary, args...)
	cmd.Env = append(os.Environ(), r.env...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (r cliRunner) runSplit(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), r.binary, args...)
	cmd.Env = append(os.Environ(), r.env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func buildTSACL(t *testing.T, tempDir string) string {
	t.Helper()
	moduleRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(tempDir, "tsacl")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/tsacl")
	cmd.Dir = moduleRoot
	if output, buildErr := cmd.CombinedOutput(); buildErr != nil {
		t.Fatalf("building tsacl: %v\n%s", buildErr, output)
	}
	return binary
}

func writePolicy(t *testing.T, dir, name, policy string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertContains(t *testing.T, output string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(output, value) {
			t.Errorf("output missing %q:\n%s", value, output)
		}
	}
}

type policyAPIServer struct {
	mu             sync.Mutex
	policy         string
	validationRuns int
	rejectedWrites int
	staleWrites    int
	successWrites  int
}

func newPolicyAPIServer(t *testing.T, policy string) *policyAPIServer {
	t.Helper()
	return &policyAPIServer{policy: policy}
}

func (s *policyAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok || username != testAPIKey || password != "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/tailnet/"+testTailnet+"/acl":
		s.handleGet(w)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/tailnet/"+testTailnet+"/acl/validate":
		s.handleValidate(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/tailnet/"+testTailnet+"/acl":
		s.handleSet(w, r)
	default:
		http.Error(w, "unexpected endpoint", http.StatusNotFound)
	}
}

func (s *policyAPIServer) handleGet(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/hujson")
	w.Header().Set("ETag", policyETag(s.policy))
	_, _ = io.WriteString(w, s.policy)
}

func (s *policyAPIServer) handleValidate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.validationRuns++
	s.mu.Unlock()
	policy := string(body)
	switch validationScenario(policy) {
	case "data-only":
		writeValidationResponse(w, "", []map[string]any{{
			"user": "data-only-user", "errors": []string{"data-only failure"},
		}})
	case "warnings-only":
		writeValidationResponse(w, "", scimWarningDetail())
	case "warnings-with-message":
		writeValidationResponse(w, "warning(s) found", scimWarningDetail())
	case "unavailable":
		writeAPIError(w, http.StatusServiceUnavailable, "backend unavailable")
	default:
		if message := validationError(policy); message != "" {
			writeAPIError(w, http.StatusOK, message)
		}
	}
}

// validationScenario reads the marker a test policy carries so the fake control
// plane can answer with a named response shape. A policy without one falls
// through to the ordinary validation path.
func validationScenario(policy string) string {
	_, after, found := strings.Cut(policy, `"validation-scenario": "`)
	if !found {
		return ""
	}
	scenario, _, found := strings.Cut(after, `"`)
	if !found {
		return ""
	}
	return scenario
}

func (s *policyAPIServer) handleSet(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	candidate := string(body)

	s.mu.Lock()
	defer s.mu.Unlock()
	if message := validationError(candidate); message != "" {
		s.rejectedWrites++
		writeAPIError(w, http.StatusBadRequest, message)
		return
	}
	if want := policyETag(s.policy); r.Header.Get("If-Match") != want {
		s.staleWrites++
		writeAPIError(w, http.StatusPreconditionFailed, "policy ETag does not match")
		return
	}
	s.policy = candidate
	s.successWrites++
	w.Header().Set("ETag", policyETag(candidate))
	w.WriteHeader(http.StatusOK)
}

func (s *policyAPIServer) assertPolicy(t *testing.T, want string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policy != want {
		t.Errorf("deployed policy mismatch:\n%s", s.policy)
	}
}

func (s *policyAPIServer) assertRequestCounts(
	t *testing.T,
	validations, rejectedWrites, staleWrites, successWrites int,
) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.validationRuns != validations || s.rejectedWrites != rejectedWrites || s.staleWrites != staleWrites ||
		s.successWrites != successWrites {
		t.Errorf("request counts = validation:%d rejected:%d stale:%d success:%d, want %d/%d/%d/%d",
			s.validationRuns, s.rejectedWrites, s.staleWrites, s.successWrites,
			validations, rejectedWrites, staleWrites, successWrites,
		)
	}
}

func validationError(policy string) string {
	if strings.Contains(policy, "tcp:not-a-port") {
		return `port range "not-a-port": too many dashes(-)`
	}
	return ""
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message": message,
		"data":    []any{},
		"status":  status,
	})
}

func scimWarningDetail() []map[string]any {
	return []map[string]any{{
		"user": "group:unknown@example.com",
		"warnings": []string{
			"group is not syncing from SCIM and will be ignored by rules in the policy file",
		},
	}}
}

func writeValidationResponse(w http.ResponseWriter, message string, data []map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"message": message, "data": data})
}

func policyETag(policy string) string {
	return fmt.Sprintf("%q", sha256Hex([]byte(policy)))
}

func trimETag(etag string) string {
	return strings.Trim(etag, `"`)
}

var metaPattern = regexp.MustCompile(`,\n  "meta": \{[^}]*\}`)

// stripMeta removes the non-deterministic trailing meta object so the rest of
// the envelope can be compared byte for byte against a golden.
func stripMeta(output string) string { return metaPattern.ReplaceAllString(output, "") }
