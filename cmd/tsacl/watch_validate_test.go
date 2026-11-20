package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rshade/tsacl/internal/aclpolicy"
	"github.com/rshade/tsacl/internal/tailapi"
	"github.com/rshade/tsacl/pkg/policycore/hujsonedit"
)

func TestCompositeTestResultTruthTable(t *testing.T) {
	t.Parallel()
	tests := []struct{ local, server, status, agreement string }{
		{statusOK, serverClean, statusOK, agreementAgree},
		{statusFailed, serverClean, statusIndeterminate, agreementDisagree},
		{statusIndeterminate, serverClean, statusIndeterminate, agreementLocalGap},
		{statusOK, serverRejected, statusFailed, agreementDisagree},
		{statusFailed, serverRejected, statusFailed, agreementAgree},
		{localInputError, serverRejected, statusFailed, agreementLocalGap},
		{statusOK, serverIndeterminate, statusIndeterminate, agreementUnavailable},
		{statusOK, serverUnavailable, statusIndeterminate, agreementUnavailable},
		{statusOK, serverSuperseded, statusIndeterminate, agreementSuperseded},
	}
	for _, test := range tests {
		t.Run(test.local+"_"+test.server, func(t *testing.T) {
			t.Parallel()
			got := compositeTestResult(options{file: "acl.hujson"}, validatedSnapshot{
				digest: "sha256:test", local: &localTestComponent{Status: test.local},
			}, serverTestComponent{Status: test.server})
			if got.Status != test.status || got.Agreement != test.agreement {
				t.Fatalf("status/agreement = %s/%s, want %s/%s", got.Status, got.Agreement, test.status, test.agreement)
			}
		})
	}
}

func TestUnavailableClassificationAndEvidence(t *testing.T) {
	t.Parallel()
	err := &tailapi.ValidationUnavailableError{
		Status: http.StatusTooManyRequests, Message: "slow down", RetryAfter: "30",
	}
	got := serverTestComponentFrom(tailapi.ValidationResult{}, err)
	if got.Status != serverUnavailable || got.Unavailable != unavailableRateLimited ||
		got.RetryAfter != "30" || got.Validation != nil {
		t.Fatalf("component = %#v", got)
	}
	// Dropping Validation is the load-bearing half: an unavailable server never
	// judged the policy, so carrying an empty result would let a consumer read
	// "no failures" as a clean verdict the control plane never gave.
	if got.HTTPStatus != http.StatusTooManyRequests || !strings.Contains(got.Message, "slow down") {
		t.Fatalf("evidence = %#v", got)
	}
}

func TestUnavailableClassificationCoversEveryStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status int
		want   string
	}{
		{http.StatusUnauthorized, unavailableAuthentication},
		{http.StatusForbidden, unavailableAuthorization},
		{http.StatusTooManyRequests, unavailableRateLimited},
		{0, unavailableTransport},
		{http.StatusInternalServerError, unavailableResponse},
	}
	for _, test := range tests {
		t.Run(test.want, func(t *testing.T) {
			t.Parallel()
			got := unavailableClass(&tailapi.ValidationUnavailableError{Status: test.status})
			if got != test.want {
				t.Fatalf("class = %s, want %s", got, test.want)
			}
		})
	}
	if got := unavailableClass(errors.New("not a validation error")); got != unavailableResponse {
		t.Fatalf("non-validation class = %s, want response", got)
	}
}

func TestValidatedWatchUsesSameBytesForDigestAndRequest(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	var posted []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		posted, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	driver := &watchDriver{marker: "}\n", step: func(int) { cancel() }}
	var stderr strings.Builder
	err := run(ctx, []string{"--tailnet", "example.com", "--api-key", "secret", "--file", path,
		"-format", formatJSON, cmdTest, "--watch", "--validate", "--interval", "1ms"},
		func(string) string { return "" }, server.Client(), server.URL, driver, &stderr)
	if err != nil {
		t.Fatalf("run: %v; stderr=%s", err, &stderr)
	}
	if string(posted) != watchPassingPolicy {
		t.Fatalf("posted bytes differ from snapshot")
	}
	got := decodeFirstRecord(t, driver)
	sum := sha256.Sum256(posted)
	wantDigest := "sha256:" + hex.EncodeToString(sum[:])
	if got.PolicyDigest != wantDigest || got.Status != statusOK || got.Agreement != agreementAgree {
		t.Fatalf("result = %#v, want digest %s ok/agree", got, wantDigest)
	}
}

// runValidatedWatch drives one composite record out of the validated loop and
// cancels, so each case below asserts a single digest's outcome rather than
// racing the poller.
func runValidatedWatch(t *testing.T, policy string, handler http.HandlerFunc) (*watchDriver, string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, policy)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	driver := &watchDriver{marker: "}\n", step: func(int) { cancel() }}
	var stderr strings.Builder
	err := run(ctx, []string{"--tailnet", "example.com", "--api-key", "secret", "--file", path,
		"-format", formatJSON, cmdTest, "--watch", "--validate", "--interval", "1ms"},
		func(string) string { return "" }, server.Client(), server.URL, driver, &stderr)
	return driver, stderr.String(), err
}

func decodeFirstRecord(t *testing.T, driver *watchDriver) result {
	t.Helper()
	records := driver.records()
	if len(records) == 0 {
		t.Fatal("no composite record emitted")
	}
	var got result
	if err := json.Unmarshal([]byte(records[0]), &got); err != nil {
		t.Fatalf("decoding %q: %v", records[0], err)
	}
	return got
}

// A rejection is the one outcome that is authoritative in both directions: it
// fails the snapshot even though the local evaluator passed it, and it must say
// so as a disagreement rather than silently overriding the local verdict.
func TestValidatedWatchLocalPassServerRejectIsFailedDisagree(t *testing.T) {
	t.Parallel()
	driver, stderr, err := runValidatedWatch(t, watchPassingPolicy,
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			// The live shape from the evidence gate behind this feature: a
			// source the local evaluator accepts and the control plane does not.
			_, _ = io.WriteString(w, `{"message":"test(s) failed","data":[{"user":"autogroup:member",`+
				`"errors":["user or host is invalid: unknown user or host: \"autogroup:member\""]}]}`)
		})
	if err != nil {
		t.Fatalf("run: %v; stderr=%s", err, stderr)
	}
	got := decodeFirstRecord(t, driver)
	if got.Status != statusFailed || got.Agreement != agreementDisagree {
		t.Fatalf("status/agreement = %s/%s, want failed/disagree", got.Status, got.Agreement)
	}
	if got.Local == nil || got.Local.Status != statusOK {
		t.Fatalf("local = %#v, want ok", got.Local)
	}
	if got.Server == nil || got.Server.Status != serverRejected {
		t.Fatalf("server = %#v, want rejected", got.Server)
	}
}

// Unavailability is the failure the composite contract exists to keep separate
// from rejection: it emits its evidence, carries no validation body a consumer
// could misread as "no failures", and stops the watcher with exit 2.
func TestValidatedWatchUnavailableEmitsEvidenceThenExitsTwo(t *testing.T) {
	t.Parallel()
	driver, stderr, err := runValidatedWatch(t, watchPassingPolicy,
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
	if exitCode(err) != exitUsage {
		t.Fatalf("error = %v, exit = %d, want %d; stderr=%s", err, exitCode(err), exitUsage, stderr)
	}
	got := decodeFirstRecord(t, driver)
	if got.Status != statusIndeterminate || got.Agreement != agreementUnavailable {
		t.Fatalf("status/agreement = %s/%s, want indeterminate/unavailable", got.Status, got.Agreement)
	}
	if got.Server == nil || got.Server.Status != serverUnavailable || got.Server.Validation != nil {
		t.Fatalf("server = %#v, want unavailable with no validation body", got.Server)
	}
	if got.Server.HTTPStatus != http.StatusInternalServerError || got.Server.Unavailable != unavailableResponse {
		t.Fatalf("evidence = %#v", got.Server)
	}
}

// The offline guarantee is the whole reason --validate is a flag rather than a
// consequence of holding credentials, and credentials in the environment are
// exactly the condition under which it would regress unnoticed.
func TestPlainWatchMakesNoRequestsWithCredentialsPresent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	driver := &watchDriver{marker: "}\n", step: func(int) { cancel() }}
	var stderr strings.Builder
	err := run(ctx, []string{"--file", path, "-format", formatJSON, cmdTest, "--watch", "--interval", "1ms"},
		func(name string) string {
			switch name {
			case "TAILSCALE_TAILNET":
				return "example.com"
			case "TAILSCALE_API_KEY":
				return "secret"
			}
			return ""
		},
		server.Client(), server.URL, driver, &stderr)
	if err != nil {
		t.Fatalf("run: %v; stderr=%s", err, &stderr)
	}
	if requests != 0 {
		t.Fatalf("plain --watch made %d HTTP requests, want 0", requests)
	}
	if got := decodeFirstRecord(t, driver); got.Local != nil || got.Server != nil {
		t.Fatalf("plain --watch emitted composite components: %#v", got)
	}
}

// An interrupt that lands while a request is in flight must not become a
// synthetic "unavailable". Both the cancellation and the completion are ready
// at once here, which is the case select resolves at random.
func TestValidatedWatchInterruptDuringRequestExitsZero(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	released := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		select {
		case <-r.Context().Done():
		case <-released:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	defer close(released)
	var stdout, stderr strings.Builder
	err := run(ctx, []string{"--tailnet", "example.com", "--api-key", "secret", "--file", path,
		"-format", formatJSON, cmdTest, "--watch", "--validate", "--interval", "1ms"},
		func(string) string { return "" }, server.Client(), server.URL, &stdout, &stderr)
	if err != nil {
		t.Fatalf("interrupt exited %d (%v), want 0; stderr=%s", exitCode(err), err, &stderr)
	}
	if strings.Contains(stdout.String(), serverUnavailable) {
		t.Fatalf("interrupt emitted a synthetic unavailable record: %s", &stdout)
	}
}

// The poller is the gate in front of every evaluation and every POST, and it is
// now shared by plain --watch and --validate, so its short-circuits are what
// keep an editor's identical rewrite off the API entirely rather than merely
// de-duplicated after the fact.
func TestStablePolicyPollerGatesRewritesAndQuietPeriod(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	logger := newLogger(io.Discard, false, nil)
	ctx := context.Background()
	poller := newStablePolicyPoller(aclpolicy.Files{}, path, []byte(watchPassingPolicy))

	// Seeded from the startup read, so an already-stable file grades on tick 1.
	if _, _, stable := poller.poll(ctx, logger); !stable {
		t.Fatal("seeded stable file did not grade on the first poll")
	}
	writeTestPolicy(t, path, watchPassingPolicy)
	if _, _, stable := poller.poll(ctx, logger); stable {
		t.Fatal("identical rewrite graded again: it would cost an evaluation and a POST")
	}
	writeTestPolicy(t, path, watchFailingPolicy)
	if _, _, stable := poller.poll(ctx, logger); stable {
		t.Fatal("changed bytes graded on first sight, defeating the quiet period")
	}
	raw, digest, stable := poller.poll(ctx, logger)
	if !stable {
		t.Fatal("changed bytes never graded after a second identical poll")
	}
	if string(raw) != watchFailingPolicy || digest != policyDigest([]byte(watchFailingPolicy)) {
		t.Fatalf("graded %q at %s, want the changed policy", raw, digest)
	}
}

// An unreadable file warns once rather than every tick, and resets the quiet
// period so the repaired file is not graded off a single poll.
func TestStablePolicyPollerWarnsOnceWhileUnreadable(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "missing.hujson")
	var stderr strings.Builder
	logger := newLogger(&stderr, false, nil)
	ctx := context.Background()
	poller := newStablePolicyPoller(aclpolicy.Files{}, path, []byte(watchPassingPolicy))
	for range 3 {
		if _, _, stable := poller.poll(ctx, logger); stable {
			t.Fatal("unreadable file reported a stable snapshot")
		}
	}
	if got := strings.Count(stderr.String(), "cannot read policy file"); got != 1 {
		t.Fatalf("warned %d times while unreadable, want 1", got)
	}
}

// A watched file that grows past --max-policy-bytes is one more unreadable
// poll: the watch warns and keeps running rather than exiting mid-session.
func TestStablePolicyPollerSkipsAnOversizeSnapshot(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy+strings.Repeat(" ", 64))
	var stderr strings.Builder
	logger := slog.New(slog.NewTextHandler(&stderr, nil))
	ctx := context.Background()
	files := aclpolicy.Files{Limits: hujsonedit.Options{MaxBytes: int64(len(watchPassingPolicy))}}
	poller := newStablePolicyPoller(files, path, []byte(watchPassingPolicy))
	for range 2 {
		if _, _, stable := poller.poll(ctx, logger); stable {
			t.Fatal("oversize file reported a stable snapshot")
		}
	}
	if got := strings.Count(stderr.String(), "config exceeds maximum size"); got != 1 {
		t.Fatalf("warned %d times about the oversize file, want 1:\n%s", got, &stderr)
	}
}

func TestValidateFlagRequiresWatch(t *testing.T) {
	t.Parallel()
	err := run(context.Background(), []string{cmdTest, "--validate"}, func(string) string { return "" },
		http.DefaultClient, "", io.Discard, io.Discard)
	if exitCode(err) != exitUsage || !strings.Contains(err.Error(), "--validate applies only to --watch") {
		t.Fatalf("error = %v, exit = %d", err, exitCode(err))
	}
}

func TestValidateWithoutCredentialsFailsBeforeTheLoop(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	err := run(context.Background(), []string{"--file", path, cmdTest, "--watch", "--validate"},
		func(string) string { return "" }, http.DefaultClient, "", io.Discard, io.Discard)
	if exitCode(err) != exitUsage || !strings.Contains(err.Error(), "--tailnet") {
		t.Fatalf("error = %v, exit = %d", err, exitCode(err))
	}
}
