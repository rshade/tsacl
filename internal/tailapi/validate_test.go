package tailapi_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/internal/aclpolicy"
	"github.com/rshade/tsacl/internal/tailapi"
)

func TestValidatePolicyResponseMatrix(t *testing.T) {
	t.Parallel()
	testCases := []validationMatrixCase{
		{name: "empty body passes", status: http.StatusOK},
		{name: "empty object passes", status: http.StatusOK, body: `{}`},
		{
			name:     "test failure is typed",
			status:   http.StatusOK,
			body:     `{"message":"test(s) failed","data":[{"user":"u","errors":["denied"]}]}`,
			wantKind: validationRejected, wantMessage: "test(s) failed", wantFailures: 1,
		},
		{
			name:     "data only fails closed",
			status:   http.StatusOK,
			body:     `{"message":"","data":[{"user":"u","errors":["denied"]}]}`,
			wantKind: validationRejected, wantFailures: 1,
		},
		{
			// Not a failure: an entry with no error text is no evidence of one,
			// and the pinned client has already dropped a documented per-detail
			// field once, so an unreadable entry means the shape moved.
			name:     "detail carrying neither errors nor warnings cannot be read as a verdict",
			status:   http.StatusOK,
			body:     `{"data":[{}]}`,
			wantKind: validationIndeterminate,
		},
		{
			name:     "unreadable detail alongside a stated error stays a rejection",
			status:   http.StatusOK,
			body:     `{"data":[{"user":"u","errors":["denied"]},{"user":"v"}]}`,
			wantKind: validationRejected, wantFailures: 1,
		},
		{
			name:     "unmodelled per-detail field is indeterminate, not a failure",
			status:   http.StatusOK,
			body:     `{"data":[{"user":"alice@example.com","notices":["deprecated syntax"]}]}`,
			wantKind: validationIndeterminate,
		},
		{
			name:         "warnings only with empty message passes",
			status:       http.StatusOK,
			body:         `{"data":[{"user":"group:x@example.com","warnings":["not syncing"]}]}`,
			wantWarnings: 1,
		},
		{
			name:   "warnings alongside a message cannot be proven clean",
			status: http.StatusOK,
			body: `{"message":"warning(s) found","data":[{"user":"group:x@example.com",` +
				`"warnings":["group is not syncing from SCIM"]}]}`,
			wantKind: validationIndeterminate, wantMessage: "warning(s) found", wantWarnings: 1,
		},
		{
			// Same verdict as the case above with the opposite-sounding message:
			// the classification is structural, so message text never decides it.
			name:   "warnings alongside a failure message land in the same state",
			status: http.StatusOK,
			body: `{"message":"test(s) failed","data":[{"user":"group:x@example.com",` +
				`"warnings":["not syncing"]}]}`,
			wantKind: validationIndeterminate, wantMessage: "test(s) failed", wantWarnings: 1,
		},
		{
			name:     "warning message cannot hide an error detail",
			status:   http.StatusOK,
			body:     `{"message":"warning(s) found","data":[{"user":"u","errors":["denied"]}]}`,
			wantKind: validationRejected, wantMessage: "warning(s) found", wantFailures: 1,
		},
		{
			name:   "mixed response fails and preserves both",
			status: http.StatusOK,
			body: `{"message":"issues found","data":[` +
				`{"user":"u","errors":["denied"]},` +
				`{"user":"group:x@example.com","warnings":["not syncing"]}]}`,
			wantKind: validationRejected, wantMessage: "issues found", wantFailures: 1, wantWarnings: 1,
		},
		// An undecodable body carries no verdict whatever the status said, so it
		// is a collection failure rather than a rejection.
		{name: "invalid json never judged the policy", status: http.StatusOK, body: `not json`,
			wantKind: validationUnavailable},
		{name: "array never judged the policy", status: http.StatusOK, body: `[]`,
			wantKind: validationUnavailable},
		{name: "null never judged the policy", status: http.StatusOK, body: `null`,
			wantKind: validationUnavailable},
		{
			// The regression that motivated typing this path: an HTML error page
			// is the ordinary shape of a gateway fault or an SSO-intercepted 401,
			// and reading it as a rejection exits "policy invalid" for a policy
			// the control plane never saw.
			name:   "html error page keeps its status instead of becoming a verdict",
			status: http.StatusServiceUnavailable, body: `<html><body>503 Service Unavailable</body></html>`,
			wantKind: validationUnavailable,
		},
		{
			name:     "html error page on an expired credential is not a verdict",
			status:   http.StatusUnauthorized,
			body:     `<html><body>Sign in</body></html>`,
			wantKind: validationUnavailable,
		},
		{
			// 400 is the generic "your request was wrong". Without per-user
			// detail there is nothing to prove the policy itself was rejected.
			name:     "bad request without detail never judged the policy",
			status:   http.StatusBadRequest,
			body:     `{"message":"unsupported content type: application/hujson"}`,
			wantKind: validationUnavailable, wantMessage: "unsupported content type: application/hujson",
		},
		{
			name:     "bad request carrying detail is a rejection the server reached",
			status:   http.StatusBadRequest,
			body:     `{"message":"parse error","data":[{"user":"u","errors":["line 3, column 2"]}]}`,
			wantKind: validationRejected, wantMessage: "parse error", wantFailures: 1,
		},
		{name: "empty data passes", status: http.StatusOK, body: `{"data":[]}`},
		{name: "null data passes", status: http.StatusOK, body: `{"data":null}`},
		{
			name: "empty server fault never judged the policy", status: http.StatusInternalServerError,
			wantKind: validationUnavailable,
		},
		{
			name:     "service unavailable never judged the policy",
			status:   http.StatusServiceUnavailable,
			body:     `{"message":"backend unavailable"}`,
			wantKind: validationUnavailable, wantMessage: "backend unavailable",
		},
		{
			name:     "expired credentials never judged the policy",
			status:   http.StatusUnauthorized,
			body:     `{"message":"invalid credentials"}`,
			wantKind: validationUnavailable, wantMessage: "invalid credentials",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				assertValidationRequest(t, request)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(testCase.status)
				_, _ = io.WriteString(w, testCase.body)
			}))
			defer server.Close()
			runValidationMatrixCase(t, server, testCase)
		})
	}
}

type validationMatrixCase struct {
	name         string
	status       int
	body         string
	wantKind     validationErrorKind
	wantMessage  string
	wantFailures int
	wantWarnings int
}

// validationErrorKind names the outcomes ValidatePolicy distinguishes, so a
// case asserts which one it got rather than only that some error appeared.
// validationUndecodable is the "fell through untyped" bucket: no case should
// reach it, because an untyped error maps to the default exit code and would
// report a policy the control plane never judged as invalid.
type validationErrorKind string

const (
	validationClean         validationErrorKind = ""
	validationRejected      validationErrorKind = "rejected"
	validationUnavailable   validationErrorKind = "unavailable"
	validationIndeterminate validationErrorKind = "indeterminate"
	validationUndecodable   validationErrorKind = "undecodable"
)

func validationErrorKindOf(err error) validationErrorKind {
	var validationErr *tailapi.ValidationError
	var unavailableErr *tailapi.ValidationUnavailableError
	var indeterminateErr *tailapi.ValidationIndeterminateError
	switch {
	case err == nil:
		return validationClean
	case errors.As(err, &validationErr):
		return validationRejected
	case errors.As(err, &unavailableErr):
		return validationUnavailable
	case errors.As(err, &indeterminateErr):
		return validationIndeterminate
	default:
		return validationUndecodable
	}
}

func assertValidationRequest(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.Path != "/api/v2/tailnet/example.com/acl/validate" {
		t.Errorf("request = %s %s", request.Method, request.URL.Path)
	}
	if request.Header.Get("Content-Type") != "application/hujson" {
		t.Errorf("Content-Type = %q", request.Header.Get("Content-Type"))
	}
	if request.Header.Get("User-Agent") != "tsacl-test" {
		t.Errorf("User-Agent = %q", request.Header.Get("User-Agent"))
	}
	username, password, ok := request.BasicAuth()
	if !ok || username != "token" || password != "" {
		t.Errorf("BasicAuth = (%q, %q, %v)", username, password, ok)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Error(err)
	}
	if string(body) != `{"grants": []}` {
		t.Errorf("request body = %q", body)
	}
}

func runValidationMatrixCase(t *testing.T, server *httptest.Server, testCase validationMatrixCase) {
	t.Helper()
	client, err := tailapi.NewClient(tailapi.Config{
		APIKey: "token", Tailnet: "example.com", BaseURL: server.URL, HTTP: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	client.UserAgent = "tsacl-test"
	result, err := tailapi.ValidatePolicy(t.Context(), client, []byte(`{"grants": []}`))
	if kind := validationErrorKindOf(err); kind != testCase.wantKind {
		t.Fatalf("error kind = %q, want %q (error %v)", kind, testCase.wantKind, err)
	}
	// The envelope must never publish a null array: every path, including the
	// ones that never reached a verdict, distinguishes "clean" from "unknown"
	// by the message and error, not by an absent slice.
	if result.Failures == nil || result.Warnings == nil {
		t.Errorf("result slices = failures:%#v warnings:%#v, want initialized", result.Failures, result.Warnings)
	}
	if result.Message != testCase.wantMessage ||
		len(result.Failures) != testCase.wantFailures || len(result.Warnings) != testCase.wantWarnings {
		t.Errorf("result = %#v", result)
	}
	switch testCase.wantKind {
	case validationRejected:
		var validationErr *tailapi.ValidationError
		_ = errors.As(err, &validationErr)
		if validationErr.Status != testCase.status {
			t.Errorf("rejection status = %d, want %d", validationErr.Status, testCase.status)
		}
		if validationErr.Message != testCase.wantMessage {
			t.Errorf("rejection message = %q, want %q", validationErr.Message, testCase.wantMessage)
		}
		if testCase.wantFailures != 0 && len(validationErr.Data) == 0 {
			t.Error("typed error dropped per-user data")
		}
	case validationUnavailable:
		var unavailableErr *tailapi.ValidationUnavailableError
		_ = errors.As(err, &unavailableErr)
		if unavailableErr.Status != testCase.status {
			t.Errorf("unavailable status = %d, want %d", unavailableErr.Status, testCase.status)
		}
	case validationIndeterminate:
		var indeterminateErr *tailapi.ValidationIndeterminateError
		_ = errors.As(err, &indeterminateErr)
		if indeterminateErr.Message != testCase.wantMessage {
			t.Errorf("indeterminate message = %q, want %q", indeterminateErr.Message, testCase.wantMessage)
		}
	case validationClean, validationUndecodable:
	}
}

// TestValidatePolicyTreatsUnreachableControlPlaneAsUnavailable covers the
// outcomes that never produce an HTTP status at all. They are the purest
// "never judged the policy" case, so they must not exit as a rejection.
func TestValidatePolicyTreatsUnreachableControlPlaneAsUnavailable(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	baseURL := server.URL
	server.Close()

	client, err := tailapi.NewClient(tailapi.Config{
		APIKey: "token", Tailnet: "example.com", BaseURL: baseURL, HTTP: http.DefaultClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tailapi.ValidatePolicy(t.Context(), client, []byte(`{}`))
	var unavailableErr *tailapi.ValidationUnavailableError
	if !errors.As(err, &unavailableErr) {
		t.Fatalf("error = %v (%T), want *ValidationUnavailableError", err, err)
	}
	if unavailableErr.Status != 0 {
		t.Errorf("status = %d, want 0: no response ever arrived", unavailableErr.Status)
	}
	// Rendering "(HTTP 0)" would invent a status the request never received.
	if strings.Contains(unavailableErr.Error(), "HTTP 0") {
		t.Errorf("error text invents a status: %s", unavailableErr.Error())
	}
	if unavailableErr.Unwrap() == nil {
		t.Error("transport error was dropped instead of wrapped")
	}
}

// TestValidatePolicyRejectsRedirectThatDropsThePolicy locks the false-green
// this guard exists to prevent: Go rewrites a 302 POST into a GET and discards
// the body, so the redirect target answers about some other resource. An
// object with no message and no data would otherwise classify as valid.
func TestValidatePolicyRejectsRedirectThatDropsThePolicy(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/tailnet/example.com/acl/validate", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/v2/tailnet/example.com/acl", http.StatusFound)
	})
	mux.HandleFunc("/api/v2/tailnet/example.com/acl", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"acl":"the deployed policy, not a verdict"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := tailapi.NewClient(tailapi.Config{
		APIKey: "token", Tailnet: "example.com", BaseURL: server.URL, HTTP: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tailapi.ValidatePolicy(t.Context(), client, []byte(`{"grants": []}`))
	var unavailableErr *tailapi.ValidationUnavailableError
	if !errors.As(err, &unavailableErr) {
		t.Fatalf("error = %v (%T), want *ValidationUnavailableError", err, err)
	}
	if !strings.Contains(unavailableErr.Error(), "never submitted") {
		t.Errorf("error text does not explain the redirect: %s", unavailableErr.Error())
	}
}

// TestValidatePolicyAcceptsRedirectThatReplaysThePolicy is the other half of
// the guard: a 307 resends the method and body, so the policy really was
// submitted and the verdict that comes back is the server's own.
func TestValidatePolicyAcceptsRedirectThatReplaysThePolicy(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/tailnet/example.com/acl/validate", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/relocated", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/relocated", func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil || string(body) != `{"grants": []}` {
			t.Errorf("replayed body = %q (err %v)", body, readErr)
		}
		_, _ = io.WriteString(w, `{}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := tailapi.NewClient(tailapi.Config{
		APIKey: "token", Tailnet: "example.com", BaseURL: server.URL, HTTP: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tailapi.ValidatePolicy(t.Context(), client, []byte(`{"grants": []}`)); err != nil {
		t.Fatalf("307 replay should still produce a verdict: %v", err)
	}
}

func TestValidatePolicyUsesInitializedClientAuthAndDefaultTailnet(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/prefix/api/v2/tailnet/-/acl/validate" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if request.Header.Get("X-Test-Auth") != "wrapped" {
			t.Errorf("wrapped auth header = %q", request.Header.Get("X-Test-Auth"))
		}
		if _, _, ok := request.BasicAuth(); ok {
			t.Error("request used BasicAuth after Auth initialized the client")
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	client, err := tailapi.NewClient(tailapi.Config{BaseURL: server.URL + "/prefix", HTTP: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	client.APIKey = "must-be-cleared"
	client.Auth = headerAuth{}
	if _, err = tailapi.ValidatePolicy(t.Context(), client, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if client.Tailnet != "-" || client.APIKey != "" {
		t.Errorf("initialized client = tailnet %q APIKey-present %v", client.Tailnet, client.APIKey != "")
	}
}

func TestValidatePolicyEscapesTailnetAsOnePathSegment(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.EscapedPath() != "/api/v2/tailnet/tenant%2Fname/acl/validate" {
			t.Errorf("escaped path = %q", request.URL.EscapedPath())
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	client, err := tailapi.NewClient(tailapi.Config{
		APIKey: "token", Tailnet: "tenant/name", BaseURL: server.URL, HTTP: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tailapi.ValidatePolicy(t.Context(), client, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
}

func TestCapturedValidationResponsesReplayThroughClassifier(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name         string
		file         string
		wantKind     validationErrorKind
		wantFailures int
	}{
		{"tests array failure", "validate_a_tests_array_failure.json", validationRejected, 1},
		{"policy assertion failure", "validate_b_policy_test_failure.json", validationRejected, 1},
		{"unknown source", "validate_b_prime_unknown_source.json", validationRejected, 1},
		// The parse error is the captured proof that message is a failure
		// channel in its own right: it carries no data at all.
		{"parse error", "validate_d_parse_error.json", validationRejected, 0},
		{"healthy", "validate_e_healthy.json", validationClean, 0},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			body, err := os.ReadFile(filepath.Join("testdata", testCase.file))
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(body)
			}))
			defer server.Close()
			client, err := tailapi.NewClient(tailapi.Config{
				APIKey: "token", Tailnet: "example.com", BaseURL: server.URL, HTTP: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := tailapi.ValidatePolicy(t.Context(), client, []byte(`{}`))
			if kind := validationErrorKindOf(err); kind != testCase.wantKind {
				t.Fatalf("captured response kind = %q, want %q (error %v)", kind, testCase.wantKind, err)
			}
			if len(result.Failures) != testCase.wantFailures {
				t.Errorf("captured failures = %#v, want %d", result.Failures, testCase.wantFailures)
			}
			if testCase.wantKind != validationRejected {
				return
			}
			var validationErr *tailapi.ValidationError
			_ = errors.As(err, &validationErr)
			if validationErr.Message == "" {
				t.Error("captured server message was dropped from the typed error")
			}
		})
	}
}

// TestCaptureManifestMatchesCommittedFixtures turns the manifest's provenance
// claim into a build failure. The bytes it records are the evidence the
// classifier is tested against, and validate_e_healthy.json is exactly two
// bytes with no trailing newline — an editor that "fixes" that silently
// destroys what the capture proves.
func TestCaptureManifestMatchesCommittedFixtures(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("testdata", "validate_capture_manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Probes []struct {
			Scenario       string `json:"scenario"`
			Available      bool   `json:"available"`
			ResponseFile   string `json:"response_file"`
			ResponseBytes  int    `json:"response_bytes"`
			ResponseSHA256 string `json:"response_sha256"`
		} `json:"probes"`
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	verified := 0
	for _, probe := range manifest.Probes {
		if !probe.Available {
			continue
		}
		verified++
		body, readErr := os.ReadFile(filepath.Join("testdata", probe.ResponseFile))
		if readErr != nil {
			t.Errorf("probe %s: %v", probe.Scenario, readErr)
			continue
		}
		if len(body) != probe.ResponseBytes {
			t.Errorf("probe %s: %s is %d bytes, manifest records %d",
				probe.Scenario, probe.ResponseFile, len(body), probe.ResponseBytes)
		}
		sum := sha256.Sum256(body)
		if digest := hex.EncodeToString(sum[:]); digest != probe.ResponseSHA256 {
			t.Errorf("probe %s: %s hashes to %s, manifest records %s",
				probe.Scenario, probe.ResponseFile, digest, probe.ResponseSHA256)
		}
	}
	if verified == 0 {
		t.Fatal("manifest recorded no available probe; the capture evidence is unverifiable")
	}
}

func TestValidateFilePreservesTypedErrorThroughPathContext(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w,
			`{"message":"test(s) failed","data":[{"user":"u","errors":["denied"]}]}`)
	}))
	defer server.Close()
	client, err := tailapi.NewClient(tailapi.Config{
		APIKey: "token", Tailnet: "example.com", BaseURL: server.URL, HTTP: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err = os.WriteFile(path, []byte(`{"grants": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = tailapi.ValidateFile(t.Context(), client, aclpolicy.Files{}, path)
	var validationErr *tailapi.ValidationError
	if !errors.As(err, &validationErr) || len(validationErr.Data) != 1 ||
		validationErr.Data[0].User != "u" || len(validationErr.Data[0].Errors) != 1 {
		t.Fatalf("wrapped error = %v, typed = %#v", err, validationErr)
	}
}

type headerAuth struct{}

func (headerAuth) HTTPClient(original *http.Client, _ string) *http.Client {
	client := *original
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = authRoundTripper{base: base}
	return &client
}

type authRoundTripper struct {
	base http.RoundTripper
}

func (transport authRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	cloned.Header.Set("X-Test-Auth", "wrapped")
	return transport.base.RoundTrip(cloned)
}

var _ tailscale.Auth = headerAuth{}

func TestValidationErrorTextIncludesStructuredDetail(t *testing.T) {
	t.Parallel()
	err := &tailapi.ValidationError{
		Status:  http.StatusOK,
		Message: "test(s) failed",
		Data: []tailapi.ValidationDetail{{
			User: "u", Errors: []string{"denied"}, Warnings: []string{"not syncing"},
		}},
	}
	for _, want := range []string{"test(s) failed", "u error: denied", "u warning: not syncing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Error() = %q, want %q", err.Error(), want)
		}
	}
}
