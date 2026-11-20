// Package tailapi provides shared access to Tailscale's policy-file API.
package tailapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/tailscale/hujson"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/internal/aclpolicy"
	"github.com/rshade/tsacl/internal/policydiff"
)

const DefaultBaseURL = "https://api.tailscale.com"

// Tailscale's OAuth scopes for the policy-file API: the read scope covers GET
// and validation, the write scope additionally replaces the policy.
//
// The endpoint path is /acl but the scopes are not named after it — these are
// the literal strings from Tailscale's trust-credentials reference, and an
// invented name like "acl:read" is rejected at the token endpoint rather than
// downscoped, so the failure lands on every request instead of just the
// privileged ones.
const (
	ScopePolicyFileRead = "policy_file:read"
	ScopePolicyFile     = "policy_file"
)

// Config configures the official Tailscale v2 API client.
type Config struct {
	APIKey            string
	OAuthClientID     string
	OAuthClientSecret string
	OAuthScopes       []string
	Tailnet           string
	BaseURL           string
	HTTP              *http.Client
}

// OAuthScopeError reports an OAuth client that was accepted but is not
// authorized for the operation's required scope. It unwraps the original error
// so callers can still classify the HTTP response, and reports that error's
// text too: the secret is already redacted by the time one is constructed, and
// a 403 body carries the only remediation the control plane offered. Naming a
// scope while discarding "policy file is managed by a GitOps integration"
// sends the operator to fix a credential that was never the problem.
type OAuthScopeError struct {
	Scope string
	Err   error
}

func (e *OAuthScopeError) Error() string {
	return fmt.Sprintf("OAuth client may lack the required scope %q: %v", e.Scope, e.Err)
}

func (e *OAuthScopeError) Unwrap() error { return e.Err }

type redactedError struct {
	message string
	err     error
}

func (e *redactedError) Error() string { return e.message }
func (e *redactedError) Unwrap() error { return e.err }

// WrapOAuthError removes the client secret from every error string that can
// reach a caller and, when an OAuth client issued the request, names the scope
// an authorization failure most likely lacked. The token endpoint reports
// invalid_scope as a normal OAuth error rather than a Tailscale APIError, so
// its text is checked as well as the typed status.
//
// clientID gates the scope attribution, and that gate is the point: a 403 is
// not scope-specific. A non-admin API key, a tailnet the credential cannot
// reach, and a GitOps-managed policy file all return one, so blaming a missing
// OAuth scope is only ever correct when an OAuth client is what authenticated.
// Without the gate every API-key 403 in the tool reports a scope the operator
// does not have and cannot grant.
func WrapOAuthError(err error, requiredScope, clientID, clientSecret string) error {
	if err == nil {
		return nil
	}
	redacted := redactError(err, clientSecret)
	if clientID == "" || !isScopeDenied(err) {
		return redacted
	}
	return &OAuthScopeError{Scope: requiredScope, Err: redacted}
}

// RedactSecret removes the client secret from an error without attributing a
// scope. It is the right wrapper for an endpoint no documented scope governs,
// where naming one would send the operator after the wrong credential.
func RedactSecret(err error, clientSecret string) error {
	if err == nil {
		return nil
	}
	return redactError(err, clientSecret)
}

// IsForbidden reports whether the control plane answered with HTTP 403.
func IsForbidden(err error) bool { return isForbidden(err) }

// redactError removes the client secret and any request URL from err's text.
// The URL is dropped because the Tailscale API embeds the tailnet name in the
// path (/api/v2/tailnet/NAME/...), and a transport failure prints it verbatim.
func redactError(err error, secret string) error {
	message := err.Error()
	if secret != "" {
		message = strings.ReplaceAll(message, secret, "[REDACTED]")
	}
	if urlErr, ok := errors.AsType[*url.Error](err); ok && urlErr.URL != "" {
		message = strings.ReplaceAll(message, urlErr.URL, "<api-url>")
	}
	if message == err.Error() {
		return err
	}
	return &redactedError{message: message, err: err}
}

func isForbidden(err error) bool {
	var apiErr tailscale.APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden {
		return true
	}
	var unavailable *ValidationUnavailableError
	return errors.As(err, &unavailable) && unavailable.Status == http.StatusForbidden
}

func isScopeDenied(err error) bool {
	if isForbidden(err) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "invalid_scope") || strings.Contains(lower, "insufficient_scope")
}

// Plan describes the validated difference between the deployed policy and a
// local candidate. ETag identifies the deployed version used for the diff.
type Plan struct {
	Diff       string
	ETag       string
	Changed    bool
	Validation ValidationResult
}

// FetchedPolicy is the deployed policy body and the version that supplied it.
type FetchedPolicy struct {
	HuJSON []byte
	ETag   string
}

// ServiceLookup records whether the control plane found a service and the
// exact name spelling it accepted. Name is empty when Exists is false.
type ServiceLookup struct {
	Name   string
	Exists bool
}

// UploadedPolicy is the exact HuJSON sent to the control plane and the new
// version returned by a successful upload. HuJSON is retained so a caller can
// safely verify a read-back when an API response omits its ETag.
type UploadedPolicy struct {
	HuJSON []byte
	ETag   string
}

// NewClient constructs the official Tailscale API client.
func NewClient(config Config) (*tailscale.Client, error) {
	hasOAuthID := config.OAuthClientID != ""
	hasOAuthSecret := config.OAuthClientSecret != ""
	if hasOAuthID != hasOAuthSecret {
		return nil, errors.New("OAuth client ID and OAuth client secret must be supplied together")
	}
	if config.APIKey != "" && hasOAuthID {
		return nil, errors.New("TAILSCALE_API_KEY and OAuth client credentials are mutually exclusive")
	}
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing Tailscale API URL: %w", err)
	}
	if err = requireSecureBaseURL(parsed); err != nil {
		return nil, err
	}
	var auth tailscale.Auth
	if hasOAuthID {
		auth = oauthAuth{
			clientID:     config.OAuthClientID,
			clientSecret: config.OAuthClientSecret,
			scopes:       append([]string(nil), config.OAuthScopes...),
		}
	}
	return &tailscale.Client{
		APIKey:  config.APIKey,
		Auth:    auth,
		Tailnet: config.Tailnet,
		BaseURL: parsed,
		HTTP:    config.HTTP,
	}, nil
}

// oauthAuth adapts the standard client-credentials implementation to the
// Tailscale client's Auth interface, and exists rather than using the pinned
// client's own tailscale.OAuth for one reason: that implementation builds its
// token source over a bare [context.Background] with no HTTP client, so the
// token request runs on [http.DefaultClient]. tsacl documents a 30s bound on
// "every Tailscale API request" and an interrupt contract for a command that is
// mid-request; an unbounded token fetch on a transport the caller never
// configured breaks both, and it is the one request that must succeed before
// any other can start. Tokens are still refreshed in memory only.
//
// If upstream adopts a caller-supplied token context, delete this and use
// tailscale.OAuth — the fork has no other reason to exist.
type oauthAuth struct {
	clientID     string
	clientSecret string
	scopes       []string
}

func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (a oauthAuth) HTTPClient(orig *http.Client, baseURL string) *http.Client {
	config := clientcredentials.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Scopes:       a.scopes,
		TokenURL:     baseURL + "/api/v2/oauth/token",
	}
	// orig carries the caller's timeout and transport and has no OAuth
	// transport of its own, so the token request inherits both without
	// recursing back through this client. The context stays Background
	// because it also drives refreshes long after any one request returns.
	tokenCtx := context.WithValue(context.Background(), oauth2.HTTPClient, orig)
	// config.TokenSource already returns a ReuseTokenSource, so it caches the
	// token until expiry; wrapping it again would allocate nothing and only
	// suggest to a reader that the inner source is uncached.
	return &http.Client{
		Transport: &oauth2.Transport{Base: orig.Transport, Source: config.TokenSource(tokenCtx)},
		// Never follow a redirect: oauth2.Transport re-adds the bearer token on
		// every hop, so a redirect to another host would hand it that host.
		CheckRedirect: refuseRedirect,
		Jar:           orig.Jar,
		Timeout:       orig.Timeout,
	}
}

// UploadFile reads path under files' limit, validates it as HuJSON, and sets
// it as the tailnet policy. The v2
// client's raw-HuJSON Set method intentionally returns only an error, so a
// request-local transport wrapper captures the successful response ETag
// without a racy second fetch or any mutation of the caller's HTTP client.
func UploadFile(
	ctx context.Context,
	client *tailscale.Client,
	files aclpolicy.Files,
	path, ifMatch string,
) (UploadedPolicy, error) {
	raw, err := files.ReadRaw(path)
	if err != nil {
		return UploadedPolicy{}, err
	}

	// Initialize defaults on the supplied client before cloning its public
	// connection settings. The initialized HTTP client already carries the
	// configured API-key or OAuth transport, so the clone does not reconfigure
	// authentication.
	_ = client.PolicyFile()
	httpClient := *client.HTTP
	transport := httpClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	capture := &etagCaptureTransport{base: transport}
	httpClient.Transport = capture
	uploadClient, err := NewClient(Config{
		APIKey:  client.APIKey,
		Tailnet: client.Tailnet,
		BaseURL: client.BaseURL.String(),
		HTTP:    &httpClient,
	})
	if err != nil {
		return UploadedPolicy{}, err
	}
	if err = uploadClient.PolicyFile().Set(ctx, string(raw), ifMatch); err != nil {
		return UploadedPolicy{}, fmt.Errorf("uploading %s: %w", path, err)
	}
	return UploadedPolicy{HuJSON: raw, ETag: capture.etag}, nil
}

type etagCaptureTransport struct {
	base http.RoundTripper
	etag string
}

func (t *etagCaptureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err == nil && response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		t.etag = response.Header.Get("ETag")
	}
	return response, err
}

// FetchPolicy reads the deployed policy without normalizing its HuJSON. The
// caller can therefore persist comments, whitespace, and key order verbatim.
func FetchPolicy(ctx context.Context, client *tailscale.Client) (FetchedPolicy, error) {
	raw, err := client.PolicyFile().Raw(ctx)
	if err != nil {
		return FetchedPolicy{}, fmt.Errorf("fetching deployed policy: %w", err)
	}
	return FetchedPolicy{HuJSON: []byte(raw.HuJSON), ETag: raw.ETag}, nil
}

// LookupService asks the control plane about one service rather than assuming
// how names returned by the collection endpoint correspond to svc: selectors.
// It sends the policy selector verbatim: the pinned client's service contract
// uses the full svc:<name> spelling for Get paths.
//
// A readable 404 is a clean Exists=false verdict. Any other failure is wrapped
// as a [ValidationUnavailableError], because an unreadable response cannot
// prove that the service is absent.
func LookupService(
	ctx context.Context,
	client *tailscale.Client,
	name string,
) (ServiceLookup, error) {
	_, err := client.Services().Get(ctx, name)
	if err == nil {
		return ServiceLookup{Name: name, Exists: true}, nil
	}
	if tailscale.IsNotFound(err) {
		return ServiceLookup{}, nil
	}

	status := 0
	if apiErr, ok := errors.AsType[tailscale.APIError](err); ok {
		status = apiErr.Status
	}
	return ServiceLookup{}, &ValidationUnavailableError{
		Status:  status,
		Message: fmt.Sprintf("looking up tailnet service %q: %v", name, err),
		Err:     err,
	}
}

// ValidateFile reads path under files' limit and asks Tailscale to validate the
// policy and run its policy tests.
func ValidateFile(
	ctx context.Context,
	client *tailscale.Client,
	files aclpolicy.Files,
	path string,
) (ValidationResult, error) {
	raw, err := files.ReadRaw(path)
	if err != nil {
		return newValidationResult(), err
	}
	result, err := ValidatePolicy(ctx, client, raw)
	if err != nil {
		return result, fmt.Errorf("validating %s: %w", path, err)
	}
	return result, nil
}

// PlanFile fetches the deployed policy, validates path without applying it,
// and returns a formatted unified diff from deployed to candidate policy.
//
// Once validation has run, every failure returns a non-nil *Plan carrying only
// Validation — Diff, ETag, and Changed stay zero — so a caller can still report
// the per-user detail and any warnings the control plane did supply rather than
// discarding diagnostics it already collected. A caller must therefore check
// the error before reading Changed, which otherwise reads as a confident "no
// changes" for a candidate that was never diffed. Validation verdicts wrap
// [ValidationError] or [ValidationIndeterminateError]; every failure before
// validation returns a nil *Plan.
func PlanFile(ctx context.Context, client *tailscale.Client, files aclpolicy.Files, path string) (*Plan, error) {
	candidate, err := files.ReadRaw(path)
	if err != nil {
		return nil, err
	}

	deployed, err := FetchPolicy(ctx, client)
	if err != nil {
		return nil, err
	}
	validation, err := ValidatePolicy(ctx, client, candidate)
	if err != nil {
		if ClassifyValidation(err).Judged() {
			return &Plan{Validation: validation}, fmt.Errorf("validating %s: %w", path, err)
		}
		return nil, fmt.Errorf("validating %s: %w", path, err)
	}

	deployedFormatted, err := hujson.Format(deployed.HuJSON)
	if err != nil {
		return &Plan{Validation: validation}, fmt.Errorf("formatting deployed policy: %w", err)
	}
	candidateFormatted, err := hujson.Format(candidate)
	if err != nil {
		return &Plan{Validation: validation}, fmt.Errorf("formatting %s: %w", path, err)
	}

	diff := policydiff.Unified("deployed", deployedFormatted, path, candidateFormatted)
	return &Plan{
		Diff:       diff,
		ETag:       deployed.ETag,
		Changed:    diff != "",
		Validation: validation,
	}, nil
}

// requireSecureBaseURL refuses a plain-HTTP API URL unless it points at the
// local machine, because the API key or OAuth token would cross the network in
// clear text. Loopback stays allowed so tests and local fakes keep working.
func requireSecureBaseURL(u *url.URL) error {
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if addr, err := netip.ParseAddr(host); err == nil && addr.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf(
		"the Tailscale API URL must use https (plain http is allowed only for loopback), got scheme %q", u.Scheme,
	)
}
