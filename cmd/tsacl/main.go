// Command tsacl makes typed edits to a Tailscale policy file and can pull,
// merge, normalize, validate, test, check, lint, plan, or upload it with
// Tailscale's policy-file API.
//
// Output contract (AX conventions, see ../../../AGENTS.md): the command result is
// written to stdout — human text by default, or a versioned JSON envelope with
// -format json — while logs and errors go to stderr. Exit codes: 0 success,
// 1 the operation or an assertion failed, 2 usage/input/collection failed, and
// 10 the question could not be settled from the policy file alone.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jaxxstorm/tscli/pkg/tscli"
	"github.com/rshade/ax-go"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/internal/aclpolicy"
	"github.com/rshade/tsacl/internal/buildinfo"
	"github.com/rshade/tsacl/internal/observedstate"
	"github.com/rshade/tsacl/internal/tailapi"
	"github.com/rshade/tsacl/pkg/policycore"
	"github.com/rshade/tsacl/pkg/policycore/cliflags"
	"github.com/rshade/tsacl/pkg/policycore/posture"
	"github.com/rshade/tsacl/pkg/policycore/sanitize"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

// schemaVersion versions the JSON result envelope and the -schema document.
// Bump it on any breaking change to either shape.
const schemaVersion = "1"

// Exit codes, documented in usage() and the -schema output.
const (
	exitOK     = 0
	exitFailed = 1 // a valid operation or policy assertion failed
	exitUsage  = 2 // usage, input, credentials, or collection failed
	// exitIndeterminate is a per-scenario code from the AX scheme's reserved
	// 10+ range. check uses it for a question the policy file alone cannot
	// settle, which is neither a denial (exit 1) nor a caller mistake (exit 2).
	exitIndeterminate = 10
)

// Result statuses reported in the envelope's "status" field.
const (
	statusOK            = "ok"
	statusFailed        = "failed"
	statusNoChanges     = "no_changes"
	statusChangesFound  = "changes_found"
	statusIndeterminate = "indeterminate"
	verdictReachable    = "reachable"
	verdictNotReachable = "not reachable"
	// verdictIndeterminate names the third answer in human output. It reads as
	// a verdict rather than an error because the policy is well-formed and the
	// question is well-posed; the fact needed to settle it just is not here.
	verdictIndeterminate = "indeterminate"

	// localInputError is the fourth value in the local component's vocabulary.
	// It has no single-shot equivalent: outside --validate a policy that will
	// not load produces no envelope at all, but the server still judges bytes
	// this evaluator could not read, and that disagreement is the evidence.
	localInputError = "input_error"

	serverClean          = "clean"
	serverRejected       = "rejected"
	serverIndeterminate  = "indeterminate"
	serverUnavailable    = "unavailable"
	serverSuperseded     = "superseded"
	agreementAgree       = "agree"
	agreementDisagree    = "disagree"
	agreementLocalGap    = "local_gap"
	agreementUnavailable = "unavailable"
	agreementSuperseded  = "superseded"

	// Sanitized classifications for a control plane that never judged the
	// policy. They describe why no verdict arrived and deliberately carry no
	// credential, URL, or response body; "response" is the catch-all for a
	// server that answered with something unusable.
	unavailableAuthentication = "authentication"
	unavailableAuthorization  = "authorization"
	unavailableRateLimited    = "rate_limited"
	unavailableTransport      = "transport"
	unavailableResponse       = "response"
)

// Command and sub-command names, output formats, and the tool name.
const (
	toolName = "tsacl"

	cmdGrant           = "grant"
	cmdGroup           = "group"
	cmdIPSet           = "ipset"
	cmdSSH             = "ssh"
	cmdNodeAttr        = "nodeattr"
	cmdTagOwner        = "tag-owner"
	cmdHost            = "host"
	cmdPosture         = "posture"
	cmdAutoApprover    = "auto-approver"
	cmdExternalTailnet = "external-tailnet"
	cmdInit            = "init"
	cmdMerge           = "merge"
	cmdNormalize       = "normalize"
	cmdValidate        = "validate"
	cmdTest            = "test"
	cmdCheck           = "check"
	cmdLint            = "lint"
	cmdJQ              = "jq"
	cmdPull            = "pull"
	cmdPlan            = "plan"
	cmdUpload          = "upload"

	subAdd    = "add"
	subRemove = "remove"
	subSet    = "set"
	subList   = "list"

	formatHuman = "human"
	formatJSON  = "json"

	indeterminateFail   = "fail"
	indeterminateWarn   = "warn"
	indeterminateIgnore = "ignore"

	commandGrantAdd              = "grant add"
	commandGrantRemove           = "grant remove"
	commandGroupAdd              = "group add"
	commandGroupRemove           = "group remove"
	commandIPSetAdd              = "ipset add"
	commandIPSetRemove           = "ipset remove"
	commandSSHAdd                = "ssh add"
	commandSSHRemove             = "ssh remove"
	commandNodeAttrAdd           = "nodeattr add"
	commandNodeAttrRemove        = "nodeattr remove"
	commandTagOwnerAdd           = "tag-owner add"
	commandHostSet               = "host set"
	commandPostureSet            = "posture set"
	commandPostureRemove         = "posture remove"
	commandAutoApproverAdd       = "auto-approver add"
	commandAutoApproverRemove    = "auto-approver remove"
	commandExternalTailnetAdd    = "external-tailnet add"
	commandExternalTailnetRemove = "external-tailnet remove"
	commandExternalTailnetList   = "external-tailnet list"
	commandTestAdd               = "test add"
	commandTestRemove            = "test remove"
	nodeAttrsTopLevel            = "nodeAttrs"

	// lintSummary is shared by commandCatalog and newLintCommand's Short text
	// so the two descriptions of "lint" cannot drift.
	lintSummary = "Statically lint policy hygiene and broad-rule test coverage " +
		"(-config currently supports broad-rule-untested allowBroad exclusions)"

	// testSummary is shared by commandCatalog and newTestCommand's Short text
	// for the same reason. --validate is appended rather than substituted: the
	// sshTests, -strict, and --indeterminate clauses are the only place either
	// surface states them, so replacing them would drop documented behavior
	// from --help and -schema at once.
	testSummary = "Run network tests locally; sshTests are preserved but not evaluated " +
		"(-strict rejects unparseable rules; --indeterminate controls only test's exit; " +
		"--watch re-runs on change and never exits non-zero for a verdict; --watch --validate " +
		"adds explicit credentialed, read-only authoritative server validation)"

	policyFormatHuJSON = "hujson"

	flagSanitize = "--sanitize"
)

// httpTimeout bounds every Tailscale API request.
const httpTimeout = 30 * time.Second

// defaultWatchInterval is the poll period for test --watch. Two consecutive
// identical polls are required before a run, so a save reaches a verdict within
// roughly twice this — fast enough for save-and-look, slow enough to be free.
const defaultWatchInterval = 500 * time.Millisecond

type options struct {
	file              string
	tailnet           string
	apiKey            string
	oauthClientID     string
	oauthClientSecret string
	ifMatch           string
	strict            bool
	roster            string
	indeterminate     indeterminateOption
}

// indeterminateOption tracks whether the global flag was explicitly supplied
// so run's PersistentPreRunE can enforce that it belongs to test without
// rejecting its default value from every other command.
//
// Set never rejects a value: pflag calls Set while walking flags that precede
// a subcommand (cobra's TraverseChildren), and an error returned from that
// walk bypasses root's FlagErrorFunc wrapping, which would misclassify the
// exit code. Validating the stored mode in PersistentPreRunE instead keeps
// every rejection on the usageError path.
type indeterminateOption struct {
	mode string
	set  bool
}

func (o *indeterminateOption) Set(value string) error {
	o.mode, o.set = value, true
	return nil
}

func (o *indeterminateOption) String() string {
	if o.mode == "" {
		return indeterminateWarn
	}
	return o.mode
}

// Type satisfies pflag.Value. The name appears in --help as the flag's
// argument placeholder.
func (o *indeterminateOption) Type() string { return "fail|warn|ignore" }

// editedHow selects how one value embedded in Message is registered.
type editedHow int

const (
	// editedAsSelector classifies the value the same way a grant selector is
	// classified: logins, hostnames, addresses, and CIDRs at identity;
	// group, tag, ipset, and posture names only at strict.
	editedAsSelector editedHow = iota
	// editedAsHostname always registers a host alias as a hostname, including
	// a name that would otherwise parse as an address or a host:port.
	editedAsHostname
	// editedAsAlias registers an externalTailnets alias.
	editedAsAlias
)

// editedValue is one identity a mutation put into Message.
type editedValue struct {
	Value string
	How   editedHow
}

func editedSelector(value string) editedValue {
	return editedValue{Value: value, How: editedAsSelector}
}

func editedHostname(value string) editedValue {
	return editedValue{Value: value, How: editedAsHostname}
}

func editedAlias(value string) editedValue {
	return editedValue{Value: value, How: editedAsAlias}
}

// result is the versioned envelope every command returns. Human rendering emits
// Message (and Diff, when present); JSON rendering emits the whole struct.
type result struct {
	SchemaVersion string             `json:"schema_version"`
	Tool          string             `json:"tool"`
	Sanitization  *sanitize.Metadata `json:"sanitization,omitempty"`
	Command       string             `json:"command"`
	Status        string             `json:"status"`
	Message       string             `json:"message"`
	File          string             `json:"file,omitempty"`
	// PolicyDigest content-addresses the exact bytes that produced this result.
	// Only watch mode sets it: a stream needs a correlator, and a digest is
	// reproducible where a timestamp is not — it also identifies what was
	// evaluated rather than when. omitempty is what keeps single-shot JSON
	// byte-identical to the pre-watch envelope.
	PolicyDigest string `json:"policy_digest,omitempty"`
	Tailnet      string `json:"tailnet,omitempty"`
	// Authentication is emitted only for OAuth so a machine consumer can audit
	// which credential class was selected without ever receiving the secret.
	Authentication string `json:"authentication,omitempty"`
	ETag           string `json:"etag,omitempty"`
	// AcceptedRemoteChanges is emitted only for upload's explicit concurrency
	// opt-out, so a machine consumer can audit that the safety guard was
	// deliberately disabled rather than mistaking it for an ordinary upload.
	AcceptedRemoteChanges bool   `json:"accepted_remote_changes,omitempty"`
	Diff                  string `json:"diff,omitempty"`
	Changed               *bool  `json:"changed,omitempty"`
	GrantIndex            *int   `json:"grant_index,omitempty"`
	// TestIndex and AssertionIDs are set only by test add/remove. A pointer keeps
	// test index zero distinct from a command that does not edit assertions.
	TestIndex    *int     `json:"test_index,omitempty"`
	AssertionIDs []string `json:"assertion_ids,omitempty"`
	ACLIndex     *int     `json:"acl_index,omitempty"`
	MergedFiles  *int     `json:"merged_files,omitempty"`
	// Access is the three-state reachability verdict. Allowed is the older
	// two-state field and is emitted only for a definite answer: an
	// indeterminate result omits it rather than serializing false, which a
	// consumer reading just that key would misread as a denial.
	Access      aclpolicy.Access   `json:"access,omitempty"`
	Allowed     *bool              `json:"allowed,omitempty"`
	Source      string             `json:"source,omitempty"`
	Destination string             `json:"destination,omitempty"`
	Port        *uint16            `json:"port,omitempty"`
	Protocol    aclpolicy.Protocol `json:"protocol,omitempty"`
	Evidence    string             `json:"evidence,omitempty"`
	Trace       []string           `json:"trace,omitempty"`
	// Assertions is a pointer so a test run with no declared tests still emits
	// "assertions": [] rather than dropping the key, while every other command
	// omits it — the same absent-versus-zero split as Changed and MergedFiles.
	Assertions *[]aclpolicy.AssertionResult `json:"assertions,omitempty"`
	// Skipped is an exception list, so absent genuinely means "nothing skipped"
	// and a plain omitempty slice is right here.
	Skipped []aclpolicy.RuleSkip `json:"skipped,omitempty"`
	// SSHTestsSkipped counts top-level sshTests assertions that were loaded but
	// not evaluated. It is a plain omitempty int for the same reason as Skipped:
	// absent genuinely means none were skipped, so a consumer never has to
	// distinguish zero from unset.
	SSHTestsSkipped int                    `json:"ssh_tests_skipped,omitempty"`
	TestSummary     *aclpolicy.TestSummary `json:"test_summary,omitempty"`
	Policy          json.RawMessage        `json:"policy,omitempty"`
	// Findings is the complete lint report. An explicit -severity threshold
	// controls the human view and exit status; when the flag is omitted, the
	// human view also keeps every finding while the default warn threshold still
	// controls exit status. The versioned JSON envelope always keeps every
	// finding so existing machine consumers do not silently lose lower tiers.
	// The pointer preserves "findings": [] for a clean lint run while every other
	// command omits the field.
	Findings *[]aclpolicy.LintFinding `json:"findings,omitempty"`
	// LintSummary counts the whole policy, matching Findings above it.
	LintSummary *aclpolicy.LintSummary `json:"lint_summary,omitempty"`
	// LintThreshold is the resolved -severity used for exit status and, when the
	// flag was explicit, the human view. It is informational in JSON; Findings
	// remains the complete report.
	LintThreshold string `json:"lint_severity_threshold,omitempty"`
	// LintSeverityExplicit distinguishes an omitted -severity (show everything,
	// fail at warn) from an explicit -severity warn (show and fail at warn). It is
	// presentation state, not part of the versioned JSON envelope.
	LintSeverityExplicit bool `json:"-"`
	// Edited lists identities embedded in Message so the sanitizer can register
	// them before rewriting prose. It is not part of the versioned JSON envelope.
	// external-tailnet list reports aliases through ExternalTailnets instead.
	Edited []editedValue `json:"-"`
	// Results carries jq's output values, and only jq sets it. The pointer is
	// the same absent-versus-empty split as Assertions and Findings: a query
	// that matched nothing still emits "results": [], which a consumer can tell
	// apart from a command that never ran a query at all.
	Results    *[]any                    `json:"results,omitempty"`
	Validation *tailapi.ValidationResult `json:"validation,omitempty"`
	Local      *localTestComponent       `json:"local,omitempty"`
	Server     *serverTestComponent      `json:"server,omitempty"`
	Agreement  string                    `json:"agreement,omitempty"`
	// ExternalTailnets is set only by external-tailnet list. The pointer keeps
	// an empty section as "external_tailnets": [] and lets every other command
	// omit the field.
	ExternalTailnets *[]aclpolicy.ExternalTailnetEntry `json:"external_tailnets,omitempty"`
	// DryRun marks a rehearsal: nothing was written, and Diff holds the change
	// a real run would have made.
	DryRun bool `json:"dry_run,omitempty"`
	// Meta carries the ax-go correlation metadata. It is the last field so the
	// envelope without it is byte-identical to the pre-ax-go output, and it is
	// emitted only in JSON mode.
	Meta *ax.Metadata `json:"meta,omitempty"`
}

type localTestComponent struct {
	Status          string                      `json:"status"`
	Message         string                      `json:"message,omitempty"`
	Assertions      []aclpolicy.AssertionResult `json:"assertions"`
	Skipped         []aclpolicy.RuleSkip        `json:"skipped,omitempty"`
	SSHTestsSkipped int                         `json:"ssh_tests_skipped,omitempty"`
	Summary         *aclpolicy.TestSummary      `json:"summary,omitempty"`
}

type serverTestComponent struct {
	Status      string                    `json:"status"`
	Validation  *tailapi.ValidationResult `json:"validation,omitempty"`
	Unavailable string                    `json:"unavailable,omitempty"`
	HTTPStatus  int                       `json:"http_status,omitempty"`
	RetryAfter  string                    `json:"retry_after,omitempty"`
	Message     string                    `json:"message,omitempty"`
}

var (
	errAssertionsFailed   = errors.New("one or more policy assertions failed")
	errReachabilityDenied = errors.New("policy does not allow the requested reachability")
	errLintFindings       = errors.New("policy lint found issues at or above the severity threshold")
	// errReachabilityIndeterminate carries exit 10. It is deliberately not a
	// usageError: the caller did nothing wrong and the policy is not at fault —
	// the answer simply is not derivable from a policy file.
	errReachabilityIndeterminate = errors.New("reachability cannot be determined from the policy file alone")
)

// usageError marks an error as an invocation problem (exit 2) rather than an
// operation failure (exit 1), so exitCode can tell "you called it wrong" from
// "it tried and failed".
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usagef(format string, a ...any) error { return usageError{fmt.Errorf(format, a...)} }

func main() { os.Exit(realMain()) }

// realMain exists so the signal handler's stop can be deferred; [os.Exit] in
// main would skip it, which gocritic's exitAfterDefer flags.
func realMain() int {
	// os.Interrupt only, not SIGTERM: make cross builds Windows, where SIGTERM is
	// declared but never delivered.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	restoreDefaultAfterCancel(ctx, stop)
	enableVirtualTerminal()
	client := &http.Client{Timeout: httpTimeout}
	apiURL := os.Getenv("TAILSCALE_API_URL")
	if apiURL == "" {
		apiURL = tailapi.DefaultBaseURL
	}
	code, _ := execute(ctx, os.Args[1:], os.Getenv, client, apiURL, os.Stdout, os.Stderr)
	return code
}

// restoreDefaultAfterCancel hands the interrupt back to the Go runtime as soon
// as ctx is cancelled, so a second Ctrl-C still hard-kills the process.
//
// [signal.NotifyContext]'s own goroutine cancels on the first signal and then
// returns without calling [signal.Stop], which leaves the signal trapped with a
// one-deep channel nothing drains. Every later interrupt is silently swallowed,
// so any command that never observes ctx — a typed edit, merge, or a watch loop
// parked in a blocked write to a full pipe — becomes killable only by SIGKILL.
// Before signal handling existed here, the default disposition ended all of
// them on the first Ctrl-C; this keeps that escape hatch.
func restoreDefaultAfterCancel(ctx context.Context, stop context.CancelFunc) {
	go func() {
		<-ctx.Done()
		stop()
	}()
}

// exitCode maps a run error onto the documented exit-code scheme.
//
// --help needs no case of its own: cobra recognizes its own help request
// before RunE, calls HelpFunc, and returns nil from Execute, so a help
// invocation reaches here as the nil case. The [flag.ErrHelp] arm this used to
// carry was a leftover from the stdlib-flag era and could never have fired —
// cobra aliases its "flag" import to pflag, whose ErrHelp is a distinct value
// from the standard library's, so the guard named a sentinel this program's
// stack cannot produce.
func exitCode(err error) int {
	var ue usageError
	var es exitStatusError
	var axErr *ax.Error
	outcome := tailapi.ClassifyValidation(err)
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &es):
		return es.code
	case errors.As(err, &axErr):
		return axErr.ExitCode()
	case errors.Is(err, errReachabilityIndeterminate), outcome == tailapi.ValidationIndeterminate:
		return exitIndeterminate
	// A control plane that never judged the policy is a collection failure, not
	// a verdict: an expired token or a 503 must not exit as "policy invalid".
	//
	// An interrupt is the same category, and saying so matters most for upload:
	// the request may already have been applied when cancellation unwound the
	// client, so exit 1 would report a definite failure for a change that can
	// have landed. Watch never reaches here — it returns nil on interrupt.
	case errors.As(err, &ue), outcome == tailapi.ValidationUnavailable,
		errors.Is(err, context.Canceled):
		return exitUsage
	default:
		return exitFailed
	}
}

// newRootCommand builds the root command and its six flag-file/credential
// persistent flags. TraverseChildren lets cobra parse each ancestor's flags as
// it walks the tree, which is what lets tag-owner add, host set, and posture
// set disable their own flag parsing (see commands.go) while --file and the
// other global flags, written before the subcommand, still bind correctly.
func newRootCommand(getenv func(string) string, opts *options) *cobra.Command {
	root := &cobra.Command{
		Use:           toolName,
		Short:         "Compile, validate, plan, and upload the tailnet ACL policy.",
		Version:       buildinfo.Version(toolName, version),
		SilenceErrors: true,
		SilenceUsage:  true,
		// A leftover positional at the root means the first token was not a
		// recognized subcommand; NoArgs turns that into the same "unknown
		// command" diagnostic dispatch() used to return.
		Args:             cobra.NoArgs,
		TraverseChildren: true,
	}
	root.SetVersionTemplate("{{.Version}}\n")

	flags := root.PersistentFlags()
	flags.StringVar(&opts.file, "file", "acl.json",
		"policy file (typed edits preserve comments in JSON and HuJSON)")
	flags.StringVar(&opts.tailnet, "tailnet", getenv("TAILSCALE_TAILNET"),
		"tailnet name or ID (default: TAILSCALE_TAILNET)")
	flags.StringVar(&opts.apiKey, "api-key", "", "Tailscale API access token (default: TAILSCALE_API_KEY)")
	flags.StringVar(&opts.oauthClientID, "oauth-client-id", "",
		"OAuth client ID (default: TAILSCALE_OAUTH_CLIENT_ID)")
	flags.StringVar(&opts.oauthClientSecret, "oauth-client-secret", "",
		"OAuth client secret (default: TAILSCALE_OAUTH_CLIENT_SECRET)")
	flags.StringVar(&opts.ifMatch, "if-match", "",
		"upload: explicit ETag overriding the policy-adjacent observed value")
	flags.BoolVar(&opts.strict, "strict", false,
		"test/check: reject a policy containing an unparseable rule instead of warning")
	flags.StringVar(&opts.roster, "roster", "",
		"test/check: PATH to a JSON login-to-role roster, asserting it is complete and authoritative")
	opts.indeterminate.mode = indeterminateWarn
	flags.Var(&opts.indeterminate, "indeterminate",
		"test only: indeterminate assertion exit policy: fail|warn|ignore (check always exits 10)")

	// Cobra's own parse failures at the resolved leaf must keep exit 2, so they
	// are wrapped as the same usageError the hand-written diagnostics use.
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})
	// cobra resolves a command's help function by walking up to the nearest
	// ancestor that set one, so an override here answers --help for the entire
	// tree unless it hands descendants back. Without the dispatch, every
	// subcommand's --help printed this whole-tool page: "tsacl lint --help"
	// listed the full command catalog, every root example, and lint's own
	// --severity/--wildcard/--config under a "Global flags:" heading that they
	// are not. Only root gets the hand-written page.
	root.SetHelpFunc(func(cmd *cobra.Command, _ []string) {
		if cmd != root {
			commandHelp(cmd)
			return
		}
		usage(cmd.OutOrStdout(), cmd.Flags())
	})
	root.InitDefaultHelpFlag()
	return root
}

// run executes the CLI and returns the command's error. The ax-go runtime has
// already written the stderr envelope by the time it returns.
func run(
	ctx context.Context,
	args []string,
	getenv func(string) string,
	httpClient *http.Client,
	apiURL string,
	stdout, stderr io.Writer,
) error {
	_, err := execute(ctx, args, getenv, httpClient, apiURL, stdout, stderr)
	return err
}

// execute runs the CLI under the ax-go runtime. It returns the process exit
// code together with the command's own error, which exitCode classifies.
func execute(
	ctx context.Context,
	args []string,
	getenv func(string) string,
	httpClient *http.Client,
	apiURL string,
	stdout, stderr io.Writer,
) (int, error) {
	var opts options
	var res *result
	format := ""
	colorRaw := colorModeAuto
	verbose := false
	showSchema := false
	sanitizeLevel := string(sanitize.Off)
	var outputSanitizer *sanitize.Sanitizer

	root := newRootCommand(getenv, &opts)
	registerGlobalFlags(root.PersistentFlags(), &format, &colorRaw, &verbose, &sanitizeLevel, &showSchema)
	root.RunE = func(cmd *cobra.Command, _ []string) error {
		if showSchema {
			return printSchema(cmd.OutOrStdout(), cmd.Flags())
		}
		usage(cmd.ErrOrStderr(), cmd.Flags())
		return usageError{errors.New("a command is required")}
	}
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		persistent := root.PersistentFlags()
		configured, sanitizeErr := configureOutputSanitizer(
			cmd, persistent, getenv, cmd.ErrOrStderr(), sanitizeLevel, opts.tailnet,
		)
		if sanitizeErr != nil {
			return sanitizeErr
		}
		outputSanitizer = configured
		resolveCredentials(&opts, getenv,
			persistent.Changed("api-key"),
			persistent.Changed("oauth-client-id") || persistent.Changed("oauth-client-secret"))
		format = resolveFormat(cmd.Context(), format)
		if format != formatHuman && format != formatJSON {
			return usagef("unknown -format %q; want human or json", format)
		}
		if _, ok := parseColorMode(colorRaw); !ok {
			return usagef("unknown -color %q; want auto, always, or never", colorRaw)
		}
		if rosterErr := validateRoster(
			cmd.Name(), opts.roster, root.PersistentFlags().Changed("roster"),
		); rosterErr != nil {
			return rosterErr
		}
		return validateIndeterminate(cmd.Name(), opts.indeterminate)
	}

	deps := commandDeps{
		opts:       &opts,
		result:     &res,
		httpClient: httpClient,
		apiURL:     apiURL,
		format:     &format,
		colorRaw:   &colorRaw,
		getenv:     getenv,
		verbose:    &verbose,
		sanitizer:  &outputSanitizer,
		axLogger:   newAxLogger(ctx, stderr),
	}
	addSubcommands(root, &deps)

	var commandErr error
	finish := func(cmd *cobra.Command, err error) error {
		err = classifyCobraError(err)
		var sanitized *result
		sanitized, err = sanitizeOutcome(withMeta(cmd.Context(), format, res), err, outputSanitizer)
		res = nil
		if renderErr := renderOutcome(cmd.OutOrStdout(), getenv, format, colorRaw, sanitized); renderErr != nil {
			err = renderErr
		}
		if err == nil {
			return nil
		}
		if commandErr == nil {
			commandErr = err
		}
		return axErrorFor(cmd.Context(), err, verdictContext(&deps.underMCP, sanitized)...)
	}
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return finish(cmd, usageError{err})
	})
	adaptTree(root, finish)

	runRoot := rootForArgs(root, cliflags.Normalize(root, args), finish)
	code := ax.Execute(ctx, runRoot, runtimeOptions(getenv, stdout, stderr, deps.axLogger)...)
	return code, withExitStatus(commandErr, code)
}

// registerGlobalFlags registers the flags every command inherits.
func registerGlobalFlags(
	flags *pflag.FlagSet,
	format, colorRaw *string,
	verbose *bool,
	sanitizeLevel *string,
	showSchema *bool,
) {
	flags.StringVar(format, "format", "", "output format: human|json")
	flags.StringVar(colorRaw, "color", colorModeAuto, "colorize human output: auto|always|never")
	flags.BoolVar(verbose, "verbose", false, "log operational detail to stderr")
	flags.StringVar(sanitizeLevel, "sanitize", string(sanitize.Off),
		"output sanitization level: off|identity|strict (a non-off TAILSCALE_SANITIZE value overrides this flag)")
	// Registered but unbound: cobra's Version field intercepts --version before
	// RunE, so no handler here would ever run. The registration must stay under
	// this exact name and usage text, which schema.golden.json locks — cobra's
	// own auto-registered flag would read "version for tsacl" and break the
	// golden.
	flags.Bool("version", false, "print version and exit")
	// Registered here so cliflags.Normalize rewrites the single-dash spellings
	// before ax.Execute runs; ax-go adopts flags that already exist.
	flags.Bool("dry-run", false, "emit the envelope without side effects")
	flags.Bool("yes", false, "confirm a confirmation-gated operation")
	flags.String("idempotency-key", "", "opaque key used to prevent duplicate-create retries")
	flags.BoolVar(showSchema, "schema", false,
		"print the machine-readable tool schema (JSON) and exit")
}

// renderOutcome writes the result envelope, if the command produced one.
func renderOutcome(stdout io.Writer, getenv func(string) string, format, colorRaw string, res *result) error {
	if res == nil {
		return nil
	}
	mode, _ := parseColorMode(colorRaw)
	return render(stdout, format, colorEnabled(format, mode, stdout, getenv), res)
}

func configureOutputSanitizer(
	cmd *cobra.Command,
	persistent *pflag.FlagSet,
	getenv func(string) string,
	stderr io.Writer,
	flagLevel, tailnet string,
) (*sanitize.Sanitizer, error) {
	resolution, err := sanitize.Resolve(
		getenv(sanitize.LevelEnv), flagLevel, persistent.Changed("sanitize"),
	)
	if err != nil {
		return nil, usageError{err}
	}
	if notice := resolution.Notice(toolName); notice != "" {
		if _, err = fmt.Fprintln(stderr, notice); err != nil {
			return nil, err
		}
	}
	if resolution.Level != sanitize.Off && unsanitizableCommand(cmd.Name()) {
		source := flagSanitize
		if resolution.EnvironmentActive {
			source = sanitize.LevelEnv
		}
		return nil, usagef(
			"%s output contains a policy or policy diff and cannot be mechanically sanitized; "+
				"unset %s or set it to off",
			cmd.CommandPath(), source,
		)
	}
	output, err := sanitize.New(sanitize.Options{
		Level: resolution.Level, Tool: toolName, Tailnet: tailnet,
		KeyHex: getenv(sanitize.KeyEnv),
	})
	if err != nil {
		return nil, usageError{err}
	}
	return output, nil
}

func unsanitizableCommand(commandName string) bool {
	return commandName == cmdNormalize || commandName == cmdPlan || commandName == cmdJQ
}

// validateIndeterminate enforces that --indeterminate, once resolvable as a
// value, is both a known mode and scoped to test. It runs from
// PersistentPreRunE — after cobra has already parsed the flag — because
// indeterminateOption.Set no longer rejects bad values itself: TraverseChildren
// parses ancestor flags outside root's FlagErrorFunc, so an error raised there
// would reach the caller unwrapped and be misclassified as exit 1 instead of
// exit 2.
func validateIndeterminate(commandName string, opt indeterminateOption) error {
	if !opt.set {
		return nil
	}
	switch opt.mode {
	case indeterminateFail, indeterminateWarn, indeterminateIgnore:
	default:
		return usagef(
			"unknown indeterminate policy %q; want %s, %s, or %s",
			opt.mode, indeterminateFail, indeterminateWarn, indeterminateIgnore,
		)
	}
	if commandName != cmdTest {
		return usagef("--indeterminate applies only to test; check always preserves its three-state verdict")
	}
	return nil
}

// validateRoster rejects --roster on every command that cannot consume it.
// A dropped roster would leave the operator believing role autogroups were
// resolved when they were not, so this is loud rather than a silent no-op.
//
// The test is an allowlist, never a denylist of the other commands: cmd.Name()
// reports the leaf name, so "tsacl grant add" arrives here as "add" and
// "tsacl posture set" as "set". A denylist naming the parents would let
// --roster through on every subcommand.
func validateRoster(commandName, path string, supplied bool) error {
	if !supplied {
		return nil
	}
	if commandName != cmdTest && commandName != cmdCheck {
		return usagef("--roster applies only to test and check; " +
			"no other command resolves role autogroups")
	}
	// An explicitly supplied but empty path is rejected here so the two halves
	// of "supplied" cannot disagree. Scope is decided by Changed(), while the
	// load below triggers on a non-empty path; without this guard `--roster ""`
	// would count as supplied for the scope check and as absent for the load,
	// degrading silently to a roster-blind run. That is exactly the "the
	// operator believes role autogroups resolved when they did not" confusion
	// this flag exists to remove, and `--roster "$UNSET_VAR"` in a CI script
	// reaches it without anyone writing an empty string on purpose.
	if strings.TrimSpace(path) == "" {
		return usagef("--roster requires a path, but was supplied with an empty value")
	}
	return nil
}

// loadRoster reads and parses the roster file. Parsing lives in policycore so
// the lowercasing matches the lookup Matcher.roleMatches performs; this half is
// only the I/O, keeping the classifier a pure function of its inputs.
//
// Every failure is fatal. Degrading to a roster-blind run would answer with
// confidence built on a file that was never read.
func loadRoster(path string) (map[string]tailscale.UserRole, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, usagef("could not read --roster %s: %v", path, err)
	}
	roster, err := policycore.ParseRoster(raw)
	if err != nil {
		return nil, usagef("could not load --roster %s: %v", path, err)
	}
	return roster, nil
}

// sanitizeOutcome applies the active sanitizer to the command result and to the
// error text that main prints on stderr. It is a no-op when sanitizing is off.
func sanitizeOutcome(res *result, err error, output *sanitize.Sanitizer) (*result, error) {
	if output == nil || output.Level() == sanitize.Off {
		return res, err
	}
	if res != nil {
		res = sanitizeResultEnvelope(res, output)
	}
	if err != nil {
		err = &sanitizedError{message: scrubText(output, err.Error()), err: err}
	}
	return res, err
}

// sanitizedError carries error text that has been through the output
// sanitizer while keeping the original in the chain, so exitCode still
// classifies it.
type sanitizedError struct {
	message string
	err     error
}

func (e *sanitizedError) Error() string { return e.message }
func (e *sanitizedError) Unwrap() error { return e.err }

func newResult(command, status, message string) *result {
	return &result{
		SchemaVersion: schemaVersion,
		Tool:          toolName,
		Command:       command,
		Status:        status,
		Message:       message,
	}
}

// render writes the result to stdout in the requested format. Human output
// prints the diff (when present) followed by the summary line; JSON output
// emits the versioned envelope. colorize adds ANSI severity color to lint human
// output; it is always false for JSON (colorEnabled enforces this), so the
// envelope stays byte-clean regardless.
func render(w io.Writer, format string, colorize bool, res *result) error {
	if format == formatJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	if res.Command == cmdNormalize {
		_, err := w.Write(res.Policy)
		return err
	}
	if res.Diff != "" {
		if _, err := io.WriteString(w, res.Diff); err != nil {
			return err
		}
	}
	if err := renderCompositeTest(w, res); err != nil {
		return err
	}
	if res.Assertions != nil {
		if err := renderAssertions(w, *res.Assertions); err != nil {
			return err
		}
	}
	reportedFindings := []aclpolicy.LintFinding(nil)
	if res.Findings != nil {
		reportedFindings = slices.Clone(*res.Findings)
		if res.LintSeverityExplicit {
			reportedFindings = lintFindingsAtLeast(
				reportedFindings,
				aclpolicy.LintSeverity(res.LintThreshold),
			)
		}
		if err := renderLintFindings(
			w, reportedFindings, aclpolicy.LintSeverity(res.LintThreshold), colorize,
		); err != nil {
			return err
		}
	}
	// Human output states the credential class on its own line rather than as a
	// suffix on Message, because Message is the same field JSON emits: folding
	// it in there would make the machine envelope's text vary by an orthogonal
	// fact that already has its own field.
	if res.Authentication != "" {
		if _, err := fmt.Fprintln(w, "tsacl: authenticated with OAuth client credentials"); err != nil {
			return err
		}
	}
	// The lint summary is the one line where counts carry severity color, so it
	// is rebuilt from the structured summary rather than reprinting res.Message.
	// Every other command keeps the plain "tsacl: <message>" line.
	if colorize && res.Command == cmdLint && res.LintSummary != nil && res.Findings != nil {
		return renderLintSummaryLine(
			w, res.File, *res.LintSummary, len(reportedFindings), aclpolicy.LintSeverity(res.LintThreshold),
		)
	}
	_, err := fmt.Fprintln(w, "tsacl:", res.Message)
	return err
}

func renderAssertions(w io.Writer, assertions []aclpolicy.AssertionResult) error {
	for _, assertion := range assertions {
		if _, err := fmt.Fprintf(
			w,
			"%s %s %s -> %s (expected %s, got %s; %s)\n",
			strings.ToUpper(string(assertion.Status)),
			assertion.ID,
			assertion.Source,
			assertion.Destination,
			assertion.Expected,
			assertion.Actual,
			assertion.Evidence,
		); err != nil {
			return err
		}
	}
	return nil
}

func renderCompositeTest(w io.Writer, res *result) error {
	if res.Local == nil || res.Server == nil {
		return nil
	}
	if _, err := fmt.Fprintf(
		w, "SNAPSHOT %s\nLOCAL %s: %s\n", res.PolicyDigest, res.Local.Status, res.Local.Message,
	); err != nil {
		return err
	}
	// The per-assertion lines are what makes the local half a peer of the
	// server half rather than a headline. Plain --watch prints them, so
	// dropping them under --validate would make the authoritative mode the
	// less informative one exactly when local and server disagree.
	if err := renderAssertions(w, res.Local.Assertions); err != nil {
		return err
	}
	_, err := fmt.Fprintf(
		w, "SERVER %s: %s\nAGREEMENT %s\n", res.Server.Status, res.Server.Message, res.Agreement,
	)
	return err
}

// lintFindingsAtLeast derives the thresholded human view without mutating the
// complete finding set carried by the JSON envelope.
func lintFindingsAtLeast(
	findings []aclpolicy.LintFinding,
	threshold aclpolicy.LintSeverity,
) []aclpolicy.LintFinding {
	reported := slices.Clone(findings)
	return slices.DeleteFunc(reported, func(finding aclpolicy.LintFinding) bool {
		return !finding.Severity.AtLeast(threshold)
	})
}

// renderLintFindings prints the findings selected for the human view, holding
// the advisory tier back to a captioned block of its own. The resolved failure
// threshold lets that caption describe this run accurately: an omitted flag
// displays advice without making it fatal, while an explicit -severity advice
// both displays it and lowers the failure floor.
func renderLintFindings(
	w io.Writer,
	findings []aclpolicy.LintFinding,
	threshold aclpolicy.LintSeverity,
	colorize bool,
) error {
	for _, finding := range findings {
		if finding.Severity != aclpolicy.LintAdvice {
			if err := renderLintFinding(w, finding, colorize); err != nil {
				return err
			}
		}
	}
	advice := slices.Clone(findings)
	advice = slices.DeleteFunc(advice, func(finding aclpolicy.LintFinding) bool {
		return finding.Severity != aclpolicy.LintAdvice
	})
	if len(advice) == 0 {
		return nil
	}
	// The caption states this run's exit behavior, not merely the default one:
	// printing "does not affect the exit code" directly above the finding that
	// produced exit 1 is the kind of claim an operator quotes in a postmortem.
	caveat := fmt.Sprintf(
		"advisory (heuristic; not a defect; these are below the %s failure floor and do not affect this run's exit code):",
		threshold,
	)
	if aclpolicy.LintAdvice.AtLeast(threshold) {
		caveat = "advisory (heuristic; not a defect, but -severity advice makes these fail this run):"
	}
	if _, err := fmt.Fprintln(w, caveat); err != nil {
		return err
	}
	for _, finding := range advice {
		if err := renderLintFinding(w, finding, colorize); err != nil {
			return err
		}
		if finding.Suggestion != "" {
			if _, err := fmt.Fprintln(w, "  suggested test:", finding.Suggestion); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderLintFinding(w io.Writer, finding aclpolicy.LintFinding, colorize bool) error {
	locator := finding.Rule
	if finding.Value != "" {
		locator = finding.Rule + " " + finding.Value
	}
	// Only the severity keyword is colored; the id, locator, and evidence stay
	// default so the line reads as one severity-tagged sentence, not a rainbow.
	prefix := paint(colorize, severityColor(finding.Severity), strings.ToUpper(string(finding.Severity)))
	_, err := fmt.Fprintf(
		w,
		"%s %s %s: %s\n",
		prefix,
		finding.ID,
		locator,
		finding.Evidence,
	)
	return err
}

// streamEmitter renders an unbounded series of results to one stream. Watch mode
// turns a single verdict into a sequence, and the two formats need opposite
// things from that: JSON drops its indentation so each envelope is one
// independently parseable NDJSON line, while human output gains a blank line
// between runs so the scroll-back reads as a red-green history. colorize is
// carried through to render but only ever affects lint output; watch mode drives
// test, so the human stream here stays plain in practice — and JSON never
// colors, so NDJSON is still parse-clean whether or not stdout is a terminal.
type streamEmitter struct {
	w         io.Writer
	format    string
	colorize  bool
	sanitizer *sanitize.Sanitizer
	meta      *ax.Metadata
	wrote     bool
}

func newStreamEmitter(
	w io.Writer,
	format string,
	colorize bool,
	sanitizer *sanitize.Sanitizer,
	meta *ax.Metadata,
) *streamEmitter {
	return &streamEmitter{w: w, format: format, colorize: colorize, sanitizer: sanitizer, meta: meta}
}

func (e *streamEmitter) emit(res *result) error {
	if e.format == formatJSON && e.meta != nil {
		stamped := *res
		stamped.Meta = e.meta
		res = &stamped
	}
	if e.sanitizer != nil && e.sanitizer.Level() != sanitize.Off {
		res = sanitizeResultEnvelope(res, e.sanitizer)
	}
	if e.format == formatJSON {
		e.wrote = true
		// No SetIndent: compact plus the encoder's trailing newline is exactly
		// one record per line, matching tailnet-flow's export stream.
		return json.NewEncoder(e.w).Encode(res)
	}
	if e.wrote {
		if _, err := io.WriteString(e.w, "\n"); err != nil {
			return err
		}
	}
	e.wrote = true
	return render(e.w, e.format, e.colorize, res)
}

// commentFromFlags validates a --comment/--overwrite-comment pair once the
// caller has already determined whether --comment was explicitly supplied.
// commentSet distinguishes an unset flag from --comment "": the empty string
// asks for a comment, and "// " is an edit nobody requested.
// --overwrite-comment alone is rejected rather than ignored, because doing
// nothing quietly would read as "the overwrite happened". Shared by all
// typed authoring commands, each of which discovers commentSet from
// cmd.Flags().Changed(commentFlagName).
func commentFromFlags(commentSet bool, text string, overwrite bool) (string, bool, error) {
	if !commentSet {
		if overwrite {
			return "", false, usagef("--%s requires --%s", overwriteFlagName, commentFlagName)
		}
		return "", false, nil
	}
	if err := aclpolicy.ValidateCommentText(text); err != nil {
		return "", false, usageError{err}
	}
	return strings.TrimSpace(text), overwrite, nil
}

// resolveGrantAdd validates grant add's flags and returns the grant to author
// together with its resolved comment. Split out of runGrantAdd to keep that
// function's cognitive complexity down; the load/dedupe/patch logic there is
// substantial enough on its own.
func resolveGrantAdd(
	source, destination, ip, srcPosture []string,
	comment string,
	commentSet, overwriteComment bool,
) (tailscale.Grant, string, bool, error) {
	comment, overwriteComment, err := commentFromFlags(commentSet, comment, overwriteComment)
	if err != nil {
		return tailscale.Grant{}, "", false, err
	}
	for _, posture := range srcPosture {
		if postureErr := aclpolicy.ValidatePostureReference(posture); postureErr != nil {
			return tailscale.Grant{}, "", false, usageError{postureErr}
		}
	}
	if len(source) == 0 || len(destination) == 0 || len(ip) == 0 {
		return tailscale.Grant{}, "", false, usagef("grant add requires at least one --src, --dst, and --ip")
	}
	grant := tailscale.Grant{
		Source:      source,
		Destination: destination,
		IP:          ip,
		SrcPosture:  srcPosture,
	}
	return grant, comment, overwriteComment, nil
}

func runGrantAdd(
	path string,
	source, destination, ip, srcPosture []string,
	comment string,
	commentSet, overwriteComment bool,
) (*result, error) {
	grant, comment, overwriteComment, err := resolveGrantAdd(
		source, destination, ip, srcPosture, comment, commentSet, overwriteComment,
	)
	if err != nil {
		return nil, err
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	grantKey, err := aclpolicy.GrantSemanticKey(grant)
	if err != nil {
		return nil, err
	}
	var matchingGrants []int
	for i := range policy.Grants {
		existingKey, keyErr := aclpolicy.GrantSemanticKey(policy.Grants[i])
		if keyErr != nil {
			return nil, keyErr
		}
		if existingKey == grantKey {
			// Without a comment there is no syntax-tree node to choose, so keep
			// the established idempotent behavior even when lint would report
			// duplicate grants.
			if comment == "" {
				return commentExistingGrant(path, comment, overwriteComment, i)
			}
			matchingGrants = append(matchingGrants, i)
		}
	}
	if len(matchingGrants) > 1 {
		return nil, fmt.Errorf(
			"cannot comment grant: duplicate grants match at indexes %v; remove duplicates first",
			matchingGrants,
		)
	}
	if len(matchingGrants) == 1 {
		return commentExistingGrant(path, comment, overwriteComment, matchingGrants[0])
	}
	grantsPresent := policy.Grants != nil
	policy.Grants = append(policy.Grants, grant)
	operation := aclpolicy.PatchAdd(policy.Grants, "grants")
	if grantsPresent {
		operation = aclpolicy.PatchAdd(grant, "grants", "-")
	}
	operations := []aclpolicy.PatchOperation{operation}
	if comment != "" {
		// "-" names the last element after the patch, which is the appended
		// grant whether the operation created the block or added into it.
		operations = append(operations, commentPatch(comment, overwriteComment, "grants", "-"))
	}
	if err = aclpolicy.WritePatch(path, operations...); err != nil {
		return nil, err
	}
	index := len(policy.Grants) - 1
	return grantResult(commandGrantAdd, statusOK,
		fmt.Sprintf("added grant %d to %s", index, path), path, index), nil
}

// commentExistingGrant handles "grant add" for a grant the policy already
// carries. A comment is the only thing such a call can still change: a grant's
// identity is its selectors, and tailscale.Grant has no comment field, so
// comment state lives in the syntax tree alone.
func commentExistingGrant(path, comment string, overwrite bool, index int) (*result, error) {
	operations, err := commentOperations(path, comment, overwrite, "grants", strconv.Itoa(index))
	if err != nil {
		return nil, err
	}
	if len(operations) == 0 {
		return grantResult(commandGrantAdd, statusNoChanges,
			fmt.Sprintf("grant %d already exists in %s", index, path), path, index), nil
	}
	if err = aclpolicy.WritePatch(path, operations...); err != nil {
		return nil, err
	}
	return grantResult(commandGrantAdd, statusOK,
		fmt.Sprintf("added comment to grant %d in %s", index, path), path, index), nil
}

func runGrantRemove(path string, index int) (*result, error) {
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(policy.Grants) {
		return nil, usagef("grant index %d is out of range; policy has %d grants", index, len(policy.Grants))
	}
	// Remove the element and keep the key, even when it empties. Security: a
	// policy with neither "acls" nor "grants" falls back to Tailscale's
	// allow-all default, while an explicit empty array denies everything, so
	// pruning the last grant would silently open the tailnet. Keeping the key
	// also keeps its comments.
	if err = aclpolicy.WritePatch(path, aclpolicy.PatchRemove("grants", strconv.Itoa(index))); err != nil {
		return nil, err
	}
	return grantResult(commandGrantRemove, statusOK,
		fmt.Sprintf("removed grant %d from %s", index, path), path, index), nil
}

func grantResult(command, status, message, path string, index int) *result {
	res := newResult(command, status, message)
	res.File = path
	res.GrantIndex = &index
	return res
}

func runDefinitionAdd(
	path string,
	kind aclpolicy.DefinitionKind,
	name string,
	members []string,
	comment string,
	commentSet, overwriteComment bool,
) (*result, error) {
	comment, overwriteComment, err := commentFromFlags(commentSet, comment, overwriteComment)
	if err != nil {
		return nil, err
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	edit, err := aclpolicy.AddDefinition(policy, kind, name, members)
	if err != nil {
		return nil, usageError{err}
	}
	return finishDefinitionAdd(path, kind, edit, comment, overwriteComment)
}

func runIPSetAdd(
	path string,
	name string,
	members []aclpolicy.IPSetMemberSpec,
	comment string,
	commentSet, overwriteComment bool,
) (*result, error) {
	comment, overwriteComment, err := commentFromFlags(commentSet, comment, overwriteComment)
	if err != nil {
		return nil, err
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	edit, err := aclpolicy.AddIPSetMembers(policy, name, members)
	if err != nil {
		return nil, usageError{err}
	}
	return finishDefinitionAdd(path, aclpolicy.DefinitionIPSet, edit, comment, overwriteComment)
}

// finishDefinitionAdd applies a validated definition edit plus any comment
// operation and renders the shared add result for both definition kinds.
func finishDefinitionAdd(
	path string,
	kind aclpolicy.DefinitionKind,
	edit aclpolicy.DefinitionEdit,
	comment string,
	overwriteComment bool,
) (*result, error) {
	topLevel := definitionTopLevel(kind)
	operations := slices.Clone(edit.Operations)
	if comment != "" {
		var commentOps []aclpolicy.PatchOperation
		var err error
		if edit.Existed {
			commentOps, err = commentOperations(path, comment, overwriteComment, topLevel, edit.Name)
		} else {
			commentOps = []aclpolicy.PatchOperation{commentPatch(comment, overwriteComment, topLevel, edit.Name)}
		}
		if err != nil {
			return nil, err
		}
		operations = append(operations, commentOps...)
	}
	command := definitionCommand(kind, subAdd)
	status := statusNoChanges
	message := fmt.Sprintf("%s %s already has the requested members in %s", kind, edit.Name, path)
	if len(operations) != 0 {
		if err := aclpolicy.WritePatch(path, operations...); err != nil {
			return nil, err
		}
		status = statusOK
		message = fmt.Sprintf("updated %s %s in %s", kind, edit.Name, path)
	}
	res := newResult(command, status, message)
	res.File = path
	res.Edited = []editedValue{editedSelector(edit.Name)}
	return res, nil
}

func runDefinitionRemove(
	path string,
	kind aclpolicy.DefinitionKind,
	name string,
	force bool,
) (*result, error) {
	canonical, err := normalizeDefinitionName(kind, name)
	if err != nil {
		return nil, usageError{err}
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	edit, err := aclpolicy.RemoveDefinition(policy, kind, canonical, force)
	if err != nil {
		return nil, err
	}
	command := definitionCommand(kind, subRemove)
	status := statusNoChanges
	message := fmt.Sprintf("%s %s not present in %s", kind, canonical, path)
	if edit.Changed() {
		if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
			return nil, err
		}
		status = statusOK
		message = fmt.Sprintf("removed %s %s from %s", kind, canonical, path)
	}
	res := newResult(command, status, message)
	res.File = path
	res.Edited = []editedValue{editedSelector(canonical)}
	return res, nil
}

func runSSHAdd(
	path string,
	spec aclpolicy.SSHRuleSpec,
	comment string,
	commentSet, overwriteComment bool,
) (*result, error) {
	comment, overwriteComment, err := commentFromFlags(commentSet, comment, overwriteComment)
	if err != nil {
		return nil, err
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	edit, err := aclpolicy.AddSSHRule(policy, spec)
	if err != nil {
		return nil, usageError{err}
	}
	ruleChanged := edit.Changed()
	if comment != "" {
		if ruleChanged {
			edit.Operations = append(edit.Operations, commentPatch(comment, overwriteComment, "ssh", "-"))
		} else {
			operations, commentErr := commentOperations(
				path, comment, overwriteComment, "ssh", strconv.Itoa(edit.RuleIndex),
			)
			if commentErr != nil {
				return nil, commentErr
			}
			edit.Operations = operations
		}
	}
	status := statusNoChanges
	message := fmt.Sprintf("SSH rule already present in %s", path)
	if edit.Changed() {
		if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
			return nil, err
		}
		status = statusOK
		if ruleChanged {
			message = fmt.Sprintf("added SSH rule %d to %s", edit.RuleIndex, path)
		} else {
			message = fmt.Sprintf("added comment to SSH rule %d in %s", edit.RuleIndex, path)
		}
	}
	res := newResult(commandSSHAdd, status, message)
	res.File = path
	return res, nil
}

func runSSHRemove(path string, spec aclpolicy.SSHRuleSpec) (*result, error) {
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	edit, err := aclpolicy.RemoveSSHRule(policy, spec)
	if err != nil {
		return nil, usageError{err}
	}
	status := statusNoChanges
	message := fmt.Sprintf("SSH rule not present in %s", path)
	if edit.Changed() {
		if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
			return nil, err
		}
		status = statusOK
		message = fmt.Sprintf("removed SSH rule(s) from %s", path)
	}
	res := newResult(commandSSHRemove, status, message)
	res.File = path
	return res, nil
}

func runSSHRemoveAt(path string, index int) (*result, error) {
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	edit, err := aclpolicy.RemoveSSHRuleAt(policy, index)
	if err != nil {
		return nil, usageError{err}
	}
	if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
		return nil, err
	}
	res := newResult(commandSSHRemove, statusOK, fmt.Sprintf("removed SSH rule %d from %s", index, path))
	res.File = path
	return res, nil
}

func runNodeAttrAdd(
	path string,
	spec aclpolicy.NodeAttrSpec,
	comment string,
	commentSet, overwriteComment bool,
) (*result, error) {
	comment, overwriteComment, err := commentFromFlags(commentSet, comment, overwriteComment)
	if err != nil {
		return nil, err
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	edit, err := aclpolicy.AddNodeAttr(policy, spec)
	if err != nil {
		return nil, usageError{err}
	}
	operations := slices.Clone(edit.Operations)
	if comment != "" {
		if edit.EntryIndex == len(policy.NodeAttrs) {
			operations = append(operations,
				commentPatch(comment, overwriteComment, nodeAttrsTopLevel, "-"))
		} else {
			commentOps, commentErr := commentOperations(
				path, comment, overwriteComment, nodeAttrsTopLevel, strconv.Itoa(edit.EntryIndex))
			if commentErr != nil {
				return nil, commentErr
			}
			operations = append(operations, commentOps...)
		}
	}
	res := newResult(commandNodeAttrAdd, statusNoChanges,
		fmt.Sprintf("node attributes already present for target set in %s", path))
	if len(operations) != 0 {
		if err = aclpolicy.WritePatch(path, operations...); err != nil {
			return nil, err
		}
		message := fmt.Sprintf("updated node attributes for target set in %s", path)
		if !edit.Changed() {
			message = fmt.Sprintf("added comment to node attributes for target set in %s", path)
		}
		res = newResult(commandNodeAttrAdd, statusOK, message)
	}
	res.File = path
	return res, nil
}

func runNodeAttrRemove(path string, spec aclpolicy.NodeAttrSpec) (*result, error) {
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	edit, err := aclpolicy.RemoveNodeAttr(policy, spec)
	if err != nil {
		return nil, usageError{err}
	}
	res := newResult(commandNodeAttrRemove, statusNoChanges,
		fmt.Sprintf("node attributes not present for target set in %s", path))
	if edit.Changed() {
		if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
			return nil, err
		}
		res = newResult(commandNodeAttrRemove, statusOK,
			fmt.Sprintf("removed node attributes for target set from %s", path))
	}
	res.File = path
	return res, nil
}

func runNodeAttrRemoveAt(path string, index int) (*result, error) {
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	edit, err := aclpolicy.RemoveNodeAttrAt(policy, index)
	if err != nil {
		return nil, usageError{err}
	}
	if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
		return nil, err
	}
	res := newResult(commandNodeAttrRemove,
		statusOK, fmt.Sprintf("removed nodeAttrs entry %d from %s", index, path))
	res.File = path
	return res, nil
}

func normalizeDefinitionName(kind aclpolicy.DefinitionKind, name string) (string, error) {
	switch kind {
	case aclpolicy.DefinitionGroup:
		return aclpolicy.NormalizeGroupName(name)
	case aclpolicy.DefinitionIPSet:
		return aclpolicy.NormalizeIPSetName(name)
	default:
		return "", fmt.Errorf("unsupported definition kind %q", kind)
	}
}

func definitionTopLevel(kind aclpolicy.DefinitionKind) string {
	if kind == aclpolicy.DefinitionIPSet {
		return "ipsets"
	}
	return "groups"
}

func definitionCommand(kind aclpolicy.DefinitionKind, subcommand string) string {
	if kind == aclpolicy.DefinitionIPSet {
		return cmdIPSet + " " + subcommand
	}
	return cmdGroup + " " + subcommand
}

// runTagOwnerAdd implements "tag-owner add TAG OWNER". args is cobra's
// already-parsed positional slice (see newTagOwnerAddCommand): pflag has
// separated --comment/--overwrite-comment from TAG and OWNER, so an owner
// name beginning with "-" needs a "--" terminator before it.
func runTagOwnerAdd(path string, args []string, comment string, commentSet, overwriteComment bool) (*result, error) {
	if len(args) != 2 { //nolint:mnd // TAG and OWNER
		return nil, usagef("usage: tsacl tag-owner add TAG OWNER")
	}
	comment, overwriteComment, err := commentFromFlags(commentSet, comment, overwriteComment)
	if err != nil {
		return nil, err
	}
	tag, owner := args[0], args[1]
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	if index := slices.Index(policy.TagOwners[tag], owner); index >= 0 {
		return commentExistingOwner(path, comment, overwriteComment, tag, owner, index)
	}
	var operation aclpolicy.PatchOperation
	switch owners := policy.TagOwners[tag]; {
	case policy.TagOwners == nil:
		operation = aclpolicy.PatchAdd(map[string][]string{tag: {owner}}, "tagOwners")
	case owners == nil:
		operation = aclpolicy.PatchAdd([]string{owner}, "tagOwners", tag)
	default:
		operation = aclpolicy.PatchAdd(owner, "tagOwners", tag, "-")
	}
	operations := []aclpolicy.PatchOperation{operation}
	if comment != "" {
		// "-" names the last element once the patch has run, which is where all
		// three branches above leave the new owner.
		operations = append(operations, commentPatch(comment, overwriteComment, "tagOwners", tag, "-"))
	}
	if err = aclpolicy.WritePatch(path, operations...); err != nil {
		return nil, err
	}
	res := newResult(commandTagOwnerAdd, statusOK, fmt.Sprintf("added owner %s to %s in %s", owner, tag, path))
	res.File = path
	res.Edited = []editedValue{editedSelector(owner), editedSelector(tag)}
	return res, nil
}

// commentExistingOwner handles "tag-owner add" for an owner the tag already
// has. Without a comment that stays the no-op it has always been; with one, the
// comment alone is the edit.
func commentExistingOwner(path, comment string, overwrite bool, tag, owner string, index int) (*result, error) {
	operations, err := commentOperations(path, comment, overwrite, "tagOwners", tag, strconv.Itoa(index))
	if err != nil {
		return nil, err
	}
	res := newResult(commandTagOwnerAdd, statusNoChanges,
		fmt.Sprintf("owner %s already owns %s in %s", owner, tag, path))
	if len(operations) > 0 {
		if err = aclpolicy.WritePatch(path, operations...); err != nil {
			return nil, err
		}
		res = newResult(commandTagOwnerAdd, statusOK,
			fmt.Sprintf("added comment to owner %s of %s in %s", owner, tag, path))
	}
	res.File = path
	res.Edited = []editedValue{editedSelector(owner), editedSelector(tag)}
	return res, nil
}

// runHostSet implements "host set NAME ADDRESS". See runTagOwnerAdd for why
// args arrives already parsed and an ADDRESS beginning with "-" needs a "--"
// terminator.
func runHostSet(path string, args []string, comment string, commentSet, overwriteComment bool) (*result, error) {
	if len(args) != 2 { //nolint:mnd // NAME and ADDRESS
		return nil, usagef("usage: tsacl host set NAME ADDRESS")
	}
	comment, overwriteComment, err := commentFromFlags(commentSet, comment, overwriteComment)
	if err != nil {
		return nil, err
	}
	name, address := args[0], args[1]
	if err = validateHostAddress(address); err != nil {
		return nil, err
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	// Skip the value operation when the address already matches, so a
	// comment-only edit really is comment-only and a repeat is reported as such.
	var operations []aclpolicy.PatchOperation
	if existing, present := policy.Hosts[name]; !present || existing != address {
		operation := aclpolicy.PatchAdd(map[string]string{name: address}, "hosts")
		if policy.Hosts != nil {
			operation = aclpolicy.PatchAdd(address, "hosts", name)
		}
		operations = append(operations, operation)
	}
	commentOps, err := commentOperations(path, comment, overwriteComment, "hosts", name)
	if err != nil {
		return nil, err
	}
	operations = append(operations, commentOps...)

	res := newResult(commandHostSet, statusNoChanges,
		fmt.Sprintf("host %s already set to %s in %s", name, address, path))
	if len(operations) > 0 {
		if err = aclpolicy.WritePatch(path, operations...); err != nil {
			return nil, err
		}
		res = newResult(commandHostSet, statusOK, fmt.Sprintf("set host %s to %s in %s", name, address, path))
	}
	res.File = path
	res.Edited = []editedValue{editedHostname(name), editedSelector(address)}
	return res, nil
}

// validateHostAddress rejects a hosts value the control plane cannot parse.
// A prefix is accepted as a prefix. Anything else must parse as an address,
// and the ParseAddr error is what the message reports.
func validateHostAddress(address string) error {
	if _, err := netip.ParsePrefix(address); err == nil {
		return nil
	}
	_, err := netip.ParseAddr(address)
	if err == nil {
		return nil
	}
	return usagef("%s is not an address: %s", address, err.Error())
}

// runPostureSet implements "posture set NAME EXPR [EXPR ...]". See
// runTagOwnerAdd for why args arrives already parsed. An argument beginning
// with "-" needs a "--" terminator before it to be treated as an EXPR at
// all, and --comment must precede the terminator; every EXPR is then
// validated before the file is touched, and an error-level diagnostic fails
// the command with the file byte-identical.
func runPostureSet(
	path string, args []string, comment string, commentSet, overwriteComment bool, stderr io.Writer,
) (*result, error) {
	if len(args) < 2 { //nolint:mnd // NAME and at least one EXPR required
		return nil, usagef("usage: tsacl posture set NAME EXPR [EXPR ...]")
	}
	comment, overwriteComment, err := commentFromFlags(commentSet, comment, overwriteComment)
	if err != nil {
		return nil, err
	}
	canonical, err := aclpolicy.NormalizePostureName(args[0])
	if err != nil {
		return nil, usageError{err}
	}
	exprs := args[1:]
	if err = validatePostureExpressions(canonical, exprs, stderr); err != nil {
		return nil, err
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	// Order-sensitive equality is the conservative reading: nothing else in the
	// tool treats a posture's expression list as an unordered set, so reordering
	// it stays a real edit.
	var operations []aclpolicy.PatchOperation
	if existing, present := policy.Postures[canonical]; !present || !slices.Equal(existing, exprs) {
		operation := aclpolicy.PatchAdd(map[string][]string{canonical: slices.Clone(exprs)}, "postures")
		if policy.Postures != nil {
			operation = aclpolicy.PatchAdd(slices.Clone(exprs), "postures", canonical)
		}
		operations = append(operations, operation)
	}
	commentOps, err := commentOperations(path, comment, overwriteComment, "postures", canonical)
	if err != nil {
		return nil, err
	}
	operations = append(operations, commentOps...)

	res := newResult(commandPostureSet, statusNoChanges,
		fmt.Sprintf("posture %s already set in %s", canonical, path))
	if len(operations) > 0 {
		if err = aclpolicy.WritePatch(path, operations...); err != nil {
			return nil, err
		}
		res = newResult(commandPostureSet, statusOK, fmt.Sprintf("set posture %s in %s", canonical, path))
	}
	res.File = path
	res.Edited = []editedValue{editedSelector(canonical)}
	return res, nil
}

// validatePostureExpressions checks each expression a posture set is about to
// write against policycore/posture's grammar and vocabularies, before the
// file is touched. An expression the control plane could not parse fails the
// command as a usageError, so the policy file stays byte-identical, the same
// contract every other authoring error keeps. Every other diagnostic — an
// unknown node: or ip: attribute, an out-of-vocabulary ip:country value —
// prints to stderr and the edit proceeds: both vocabularies are editorial
// snapshots that go stale, and an authoring command that refuses a value the
// server accepts is worse than one that warns. lint's posture-invalid rule
// stays strict about the same values, where rejecting is the point.
func validatePostureExpressions(name string, exprs []string, stderr io.Writer) error {
	var invalid []string
	for _, expr := range exprs {
		for _, diagnostic := range posture.Validate(expr) {
			if diagnostic.Kind != posture.DiagnosticUnparseable {
				fmt.Fprintf(stderr, "tsacl: warning: posture %s expression %q: %s\n",
					name, expr, diagnostic.Reason)
				continue
			}
			invalid = append(invalid, fmt.Sprintf("expression %q: %s", expr, diagnostic.Reason))
		}
	}
	if len(invalid) > 0 {
		return usagef("posture %s has an expression the control plane would reject: %s",
			name, strings.Join(invalid, "; "))
	}
	return nil
}

func runPostureRemove(path string, args []string) (*result, error) {
	if len(args) != 1 {
		return nil, usagef("usage: tsacl posture remove NAME")
	}
	canonical, err := aclpolicy.NormalizePostureName(args[0])
	if err != nil {
		return nil, usageError{err}
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	if _, ok := policy.Postures[canonical]; !ok {
		res := newResult(commandPostureRemove, statusNoChanges,
			fmt.Sprintf("posture %s not present in %s", canonical, path))
		res.File = path
		res.Edited = []editedValue{editedSelector(canonical)}
		return res, nil
	}
	// Remove the member, then prune "postures" if nothing is left — see runGrantRemove.
	if err = aclpolicy.WritePatch(
		path, aclpolicy.PatchRemove("postures", canonical), aclpolicy.PatchPruneEmpty("postures"),
	); err != nil {
		return nil, err
	}
	res := newResult(commandPostureRemove, statusOK,
		fmt.Sprintf("removed posture %s from %s", canonical, path))
	res.File = path
	res.Edited = []editedValue{editedSelector(canonical)}
	return res, nil
}

// resolveAutoApproverTarget enforces the exactly-one-section rule shared by
// auto-approver add and remove and returns the canonical route, or "" when
// the edit targets the exit-node list.
func resolveAutoApproverTarget(command, route string, exitNode bool) (string, error) {
	switch {
	case exitNode && strings.TrimSpace(route) != "":
		return "", usagef("%s takes either --route or --exit-node, not both", command)
	case exitNode:
		return "", nil
	case strings.TrimSpace(route) == "":
		return "", usagef("%s requires --route CIDR or --exit-node", command)
	default:
		canonical, err := aclpolicy.NormalizeAutoApproverRoute(route)
		if err != nil {
			return "", usageError{err}
		}
		return canonical, nil
	}
}

// autoApproverTargetName phrases the edited section for result messages.
func autoApproverTargetName(route string) string {
	if route == "" {
		return "exitNode"
	}
	return "route " + route
}

// editedRoute registers the CIDR a route message names. An exit-node edit has
// no CIDR in its message, so it records nothing.
func editedRoute(route string) []editedValue {
	if route == "" {
		return nil
	}
	return []editedValue{editedSelector(route)}
}

// runAutoApproverAdd implements "auto-approver add". The approver list merges
// into an existing route entry rather than replacing it, and a repeat is a
// no-op — see aclpolicy.AddRouteApprovers.
func runAutoApproverAdd(
	path, route string,
	exitNode bool,
	approvers []string,
	comment string,
	commentSet, overwriteComment bool,
) (*result, error) {
	target, err := resolveAutoApproverTarget(commandAutoApproverAdd, route, exitNode)
	if err != nil {
		return nil, err
	}
	comment, overwriteComment, err = commentFromFlags(commentSet, comment, overwriteComment)
	if err != nil {
		return nil, err
	}
	if len(approvers) == 0 {
		return nil, usagef("auto-approver add requires at least one --approver")
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	var edit aclpolicy.AutoApproverEdit
	if target == "" {
		edit, err = aclpolicy.AddExitNodeApprovers(policy, approvers)
	} else {
		edit, err = aclpolicy.AddRouteApprovers(policy, target, approvers)
	}
	if err != nil {
		return nil, usageError{err}
	}
	operations := slices.Clone(edit.Operations)
	// edit.Route, not target: a policy that spells the key unmasked keeps that
	// spelling, and the comment has to name the member the patch actually
	// touched.
	commentOps, err := commentOperations(
		path, comment, overwriteComment, aclpolicy.AutoApproverSegments(edit.Route)...)
	if err != nil {
		return nil, err
	}
	operations = append(operations, commentOps...)

	name := autoApproverTargetName(edit.Route)
	res := newResult(commandAutoApproverAdd, statusNoChanges,
		fmt.Sprintf("approvers already present for %s in %s", name, path))
	if len(operations) > 0 {
		if err = aclpolicy.WritePatch(path, operations...); err != nil {
			return nil, err
		}
		// An approver the list already carries produces no edit operation, so a
		// --comment on that repeat is the whole change. Reporting it as "added
		// approvers" would claim an addition the file does not contain — the
		// distinction commentExistingOwner draws for "tag-owner add".
		message := fmt.Sprintf("added approvers to %s in %s", name, path)
		if !edit.Changed() {
			message = fmt.Sprintf("added comment to %s in %s", name, path)
		}
		res = newResult(commandAutoApproverAdd, statusOK, message)
	}
	res.File = path
	res.Edited = editedRoute(edit.Route)
	return res, nil
}

// runAutoApproverRemove implements "auto-approver remove". Removing the last
// approver of a route prunes the route key rather than leaving an empty list
// behind — see aclpolicy.RemoveRouteApprovers.
func runAutoApproverRemove(path, route string, exitNode bool, approvers []string) (*result, error) {
	target, err := resolveAutoApproverTarget(commandAutoApproverRemove, route, exitNode)
	if err != nil {
		return nil, err
	}
	if len(approvers) == 0 {
		return nil, usagef("auto-approver remove requires at least one --approver")
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	var edit aclpolicy.AutoApproverEdit
	if target == "" {
		edit, err = aclpolicy.RemoveExitNodeApprovers(policy, approvers)
	} else {
		edit, err = aclpolicy.RemoveRouteApprovers(policy, target, approvers)
	}
	if err != nil {
		return nil, usageError{err}
	}
	name := autoApproverTargetName(edit.Route)
	res := newResult(commandAutoApproverRemove, statusNoChanges,
		fmt.Sprintf("approvers not present for %s in %s", name, path))
	if edit.Changed() {
		if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
			return nil, err
		}
		res = newResult(commandAutoApproverRemove, statusOK,
			fmt.Sprintf("removed approvers from %s in %s", name, path))
	}
	res.File = path
	res.Edited = editedRoute(edit.Route)
	return res, nil
}

// loadForEdit validates the complete typed policy before a raw HuJSON patch is
// selected and written. DisallowUnknownFields makes this the data-loss guard:
// an edit cannot silently discard policy data the pinned schema does not model.
func loadForEdit(path string) (*aclpolicy.Policy, error) {
	return aclpolicy.Load(path)
}

func runTestAdd(
	path, source string, deny, accept []string, postureAttrFlags []string, stderr io.Writer,
) (*result, error) {
	return runTestEdit(
		commandTestAdd, path, source, deny, accept, postureAttrFlags, stderr,
		aclpolicy.AddAssertions,
		"test assertions already present in %s",
		"added %d test assertion(s) to %s",
	)
}

func runTestRemove(
	path, source string, deny, accept []string, postureAttrFlags []string, stderr io.Writer,
) (*result, error) {
	return runTestEdit(
		commandTestRemove, path, source, deny, accept, postureAttrFlags, stderr,
		aclpolicy.RemoveAssertions,
		"test assertions not present in %s",
		"removed %d test assertion(s) from %s",
	)
}

// runTestEdit is the shared body of test add and test remove: validate the
// flags, parse and warn on the posture attributes, apply the edit, and patch
// the file only when it changed. The apply argument is the one difference
// between the two commands.
func runTestEdit(
	command, path, source string,
	deny, accept []string,
	postureAttrFlags []string,
	stderr io.Writer,
	apply func(*aclpolicy.Policy, string, []string, []string, map[string]any) (aclpolicy.TestEdit, error),
	noChangeFormat, changeFormat string,
) (*result, error) {
	if strings.TrimSpace(source) == "" {
		return nil, usagef("%s requires --src", command)
	}
	if len(deny) == 0 && len(accept) == 0 {
		return nil, usagef("%s requires at least one --deny or --accept", command)
	}
	attrs, err := aclpolicy.ParsePostureAttrs(postureAttrFlags)
	if err != nil {
		return nil, usageError{err}
	}
	for _, warning := range aclpolicy.PostureAttrWarnings(attrs) {
		fmt.Fprintln(stderr, "tsacl: warning:", warning)
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	edit, err := apply(policy, source, deny, accept, attrs)
	if err != nil {
		return nil, usageError{err}
	}
	status := statusNoChanges
	message := fmt.Sprintf(noChangeFormat, path)
	if edit.Changed() {
		if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
			return nil, err
		}
		status = statusOK
		count := len(edit.Operations)
		if command == commandTestRemove {
			count = len(edit.AssertionIDs)
		}
		message = fmt.Sprintf(changeFormat, count, path)
	}
	return testEditResult(command, status, message, path, edit), nil
}

func testEditResult(command, status, message, path string, edit aclpolicy.TestEdit) *result {
	res := newResult(command, status, message)
	res.File = path
	res.AssertionIDs = edit.AssertionIDs
	if edit.TestIndex >= 0 {
		res.TestIndex = &edit.TestIndex
	}
	return res
}

// Comment flags are registered per command rather than globally. Only the typed
// authoring commands can name the node a comment belongs to, and a global flag
// would be quietly accepted by every command that cannot.
const (
	commentFlagName   = "comment"
	overwriteFlagName = "overwrite-comment"
)

func registerCommentFlags(flags *pflag.FlagSet, text *string, overwrite *bool) {
	flags.StringVar(text, commentFlagName, "", "attach TEXT to the authored entry as a leading // comment")
	flags.BoolVar(overwrite, overwriteFlagName, false,
		"replace the entry's existing comments instead of appending to them")
}

// commentPatch builds the operation that authors comment onto a node the same
// call is creating. It needs no duplicate check: a node that does not exist yet
// cannot already carry a comment.
func commentPatch(comment string, overwrite bool, segments ...string) aclpolicy.PatchOperation {
	if overwrite {
		return aclpolicy.PatchCommentOverwrite(comment, segments...)
	}
	return aclpolicy.PatchComment(comment, segments...)
}

// commentOperations returns the operation that authors comment onto an entry
// that already exists, or none when the entry already reads that way.
//
// Whether this is a change is decided from the same LeadingComments the writer
// suppresses duplicates with, so a command cannot report a change for a write
// that changed nothing.
func commentOperations(path, comment string, overwrite bool, segments ...string) ([]aclpolicy.PatchOperation, error) {
	if comment == "" {
		return nil, nil
	}
	existing, err := aclpolicy.LeadingComments(path, segments...)
	if err != nil {
		return nil, err
	}
	unchanged := slices.Contains(existing, comment)
	if overwrite {
		unchanged = slices.Equal(existing, []string{comment})
	}
	if unchanged {
		return nil, nil
	}
	return []aclpolicy.PatchOperation{commentPatch(comment, overwrite, segments...)}, nil
}

const mergeSummary = "Merge ACL sources: compile directories (--dir) or merge one snippet into a base (--base, --add)"

type mergeRequest struct {
	file, base, add, out string
	dirs                 []string
	// write stores the merged document. A nil write is aclpolicy.WriteRaw;
	// a rehearsal substitutes a capture so nothing reaches the disk.
	write func(path string, data []byte) error
}

func runMerge(req mergeRequest) (*result, error) {
	pair := req.base != "" || req.add != ""
	switch {
	case pair && len(req.dirs) != 0:
		return nil, usagef("merge takes either --dir or --base with --add, not both")
	case pair && (req.base == "" || req.add == ""):
		return nil, usagef("merge --base and --add must be given together")
	case !pair && len(req.dirs) == 0:
		return nil, usagef("merge requires at least one --dir, or --base with --add")
	}
	write := req.write
	if write == nil {
		write = aclpolicy.WriteRaw
	}
	if pair {
		return runMergePair(req.base, req.add, req.out, write)
	}
	path := req.out
	if path == "" {
		path = req.file
	}
	data, paths, err := aclpolicy.MergeDirectories(req.dirs, path)
	if err != nil {
		return nil, err
	}
	if err = write(path, data); err != nil {
		return nil, err
	}
	merged := len(paths)
	res := newResult(cmdMerge, statusOK, fmt.Sprintf("merged %d ACL files into %s", merged, path))
	res.File = path
	res.MergedFiles = &merged
	return res, nil
}

// runMergePair deep-merges one snippet into a base policy and, unlike the
// directory path, keeps the HuJSON comments and layout of both inputs. It is
// the reconciliation step after a stale-ETag upload refusal.
func runMergePair(base, add, out string, write func(string, []byte) error) (*result, error) {
	if out == "" {
		out = base
	}
	data, err := aclpolicy.MergePair(base, add)
	if err != nil {
		return nil, err
	}
	if err = write(out, data); err != nil {
		return nil, err
	}
	merged := 2
	res := newResult(cmdMerge, statusOK, fmt.Sprintf("merged %s into %s", add, out))
	res.File = out
	res.MergedFiles = &merged
	return res, nil
}

func runNormalize(path string) (*result, error) {
	standard, err := aclpolicy.Normalize(path)
	if err != nil {
		return nil, usagef("could not normalize policy: %v", err)
	}
	res := newResult(cmdNormalize, statusOK, fmt.Sprintf("normalized %s", path))
	res.File = path
	res.Policy = json.RawMessage(standard)
	return res, nil
}

// runInit creates the smallest valid policy document for typed authoring. It
// deliberately refuses to replace an existing file: init is a bootstrap, not
// an alternate upload path or a way to discard comments from a pulled policy.
func runInit(path string) (*result, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, usagef("refusing to overwrite existing policy file %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, usagef("checking policy file %s: %v", path, err)
	}
	if err := aclpolicy.WriteRaw(path, []byte("{}\n")); err != nil {
		return nil, usagef("initializing policy file %s: %v", path, err)
	}
	res := newResult(cmdInit, statusOK, fmt.Sprintf("initialized empty policy in %s", path))
	res.File = path
	return res, nil
}

func runValidate(
	ctx context.Context,
	opts options,
	httpClient *http.Client,
	apiURL string,
	logger *slog.Logger,
) (*result, error) {
	client, err := apiClient(opts, httpClient, apiURL, tailapi.ScopePolicyFileRead)
	if err != nil {
		return nil, err
	}
	validation, err := tailapi.ValidateFile(ctx, client, opts.file)
	err = tailapi.WrapOAuthError(err, tailapi.ScopePolicyFileRead, opts.oauthClientID, opts.oauthClientSecret)
	status := validationEnvelopeStatus(err)
	if status == "" {
		return nil, err
	}
	logValidationWarnings(ctx, logger, validation)
	message := fmt.Sprintf("%s is valid", opts.file)
	switch status {
	case statusIndeterminate:
		message = fmt.Sprintf("%s could not be proven valid", opts.file)
	case statusFailed:
		message = fmt.Sprintf("%s is invalid", opts.file)
	}
	res := newResult(cmdValidate, status, message)
	res.File = opts.file
	res.Tailnet = opts.tailnet
	res.Authentication = authenticationName(opts)
	res.Validation = &validation
	return res, err
}

// validationEnvelopeStatus maps a validation outcome onto an envelope status.
// The empty string means the control plane never reached a verdict, so stdout
// carries no result at all rather than reporting a policy the server never read
// as invalid.
func validationEnvelopeStatus(err error) string {
	switch tailapi.ClassifyValidation(err) {
	case tailapi.ValidationClean:
		return statusOK
	case tailapi.ValidationIndeterminate:
		return statusIndeterminate
	case tailapi.ValidationRejected:
		return statusFailed
	case tailapi.ValidationUnavailable, tailapi.ValidationNotAttempted:
		return ""
	default:
		return ""
	}
}

func logValidationWarnings(ctx context.Context, logger *slog.Logger, validation tailapi.ValidationResult) {
	for _, detail := range validation.Warnings {
		for _, warning := range detail.Warnings {
			logger.WarnContext(ctx, "ACL validation warning", "user", detail.User, "warning", warning)
		}
	}
}

func runTest(
	ctx context.Context,
	opts options,
	testOpts testOptions,
	logger *slog.Logger,
	emitter *streamEmitter,
	httpClient *http.Client,
	apiURL string,
) (*result, error) {
	// The same rule run already applies to --indeterminate outside test: a flag
	// that cannot mean anything here is a caller mistake, not a no-op. Its only
	// effect is on the exit code, and watch pins the verdict's exit code to 0.
	if testOpts.watch && opts.indeterminate.set {
		return nil, usagef(
			"--indeterminate has no effect under --watch, which never exits non-zero for a verdict; drop one of them",
		)
	}
	if testOpts.watch {
		if testOpts.validate {
			client, err := apiClient(opts, httpClient, apiURL, tailapi.ScopePolicyFileRead)
			if err != nil {
				return nil, err
			}
			return nil, watchValidatedTests(ctx, opts, testOpts, logger, emitter, client)
		}
		// Returning a nil result is what makes run skip its single final render:
		// watch has already written every verdict it is going to write.
		return nil, watchTests(ctx, opts, testOpts, logger, emitter)
	}
	return evaluatePolicyTests(ctx, opts, logger)
}

// testOptions carries the test subcommand's own flags. --indeterminate is not
// among them: it is a global flag, parsed by run before the subcommand is known.
type testOptions struct {
	watch    bool
	validate bool
	interval time.Duration
}

// watchTests re-runs the assertions whenever the policy file's contents change.
// It polls rather than subscribing to filesystem events: aclpolicy.WriteRaw
// replaces the file with CreateTemp + Rename, as does every editor worth using,
// and a watch registered on a file does not survive a rename. Polling
// re-resolves the path every tick and adds no dependency.
func watchTests(
	ctx context.Context,
	opts options,
	testOpts testOptions,
	logger *slog.Logger,
	emitter *streamEmitter,
) error {
	// A file unreadable at startup is a caller mistake — a typo in --file — not a
	// transient mid-save state. Fail loudly rather than polling a path forever.
	seed, err := os.ReadFile(opts.file)
	if err != nil {
		return usagef("could not read policy for watch: %v", err)
	}
	logger.InfoContext(ctx, "watching policy file",
		"file", opts.file, "interval", testOpts.interval)
	poller := newStablePolicyPoller(opts.file, seed)

	ticker := time.NewTicker(testOpts.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// An interrupt is not a verdict, and a watch loop has no single point
			// in time to report. Returning nil is what pins --watch to exit 0.
			return nil
		case <-ticker.C:
		}

		raw, digest, stable := poller.poll(ctx, logger)
		if !stable {
			continue
		}
		res, evalErr := evaluatePolicyTestBytes(ctx, opts, raw, logger)
		if res == nil {
			// No envelope exists for this case outside watch mode either, so
			// inventing one here would make the stream a superset of the
			// single-shot contract. Only events with no verdict reach stderr.
			logger.WarnContext(ctx, "policy file did not produce a verdict",
				"file", opts.file, "digest", digest, "error", evalErr)
			continue
		}
		res.PolicyDigest = digest
		// evalErr is discarded on purpose when a verdict exists: the envelope
		// already carries it as status, and the exit code it selects is 0 here.
		if emitErr := emitter.emit(res); emitErr != nil {
			// A failed write is the watcher's own failure, not a verdict. Exit 2
			// keeps exit 1 meaning exactly one thing across the tool: a check
			// failed. On Unix a closed reader on stdout (e.g. `| head -1`) does
			// not reach here: the Go runtime raises SIGPIPE on the failed write
			// and the process dies with 141 before emit returns. That only
			// happens on the *next* emit, though — a broken pipe is detected by
			// writing, and nothing is written between saves, so the loop polls
			// on until the policy changes. Windows has no SIGPIPE, so the same
			// closed reader reaches here as an ordinary error, same as a full
			// disk on either platform.
			return usagef("could not write watch output: %v", emitErr)
		}
	}
}

// stablePolicyPoller turns one tick into "these exact bytes are stable and not
// yet graded". Both watch loops share it so the quiet period, the
// identical-rewrite suppression, and the warn-once read failure cannot drift
// between plain --watch and --watch --validate; a change to the debounce is a
// change to one function, not two that only look alike.
type stablePolicyPoller struct {
	file       string
	pending    string
	last       string
	readFailed bool
}

// newStablePolicyPoller seeds pending from the startup read, which lets an
// already-stable file reach its first verdict after one tick instead of two.
func newStablePolicyPoller(file string, seed []byte) *stablePolicyPoller {
	return &stablePolicyPoller{file: file, pending: policyDigest(seed)}
}

// poll reports the newest stable, not-yet-graded snapshot and whether one
// exists. There is none when the file is unreadable, unchanged since the last
// verdict, or has been seen only once so far.
//
// The returned bytes are freshly allocated per call and retained nowhere here,
// so the caller owns them outright — which is what lets --validate hash,
// evaluate, and POST one slice without copying it first.
func (p *stablePolicyPoller) poll(ctx context.Context, logger *slog.Logger) ([]byte, string, bool) {
	raw, err := os.ReadFile(p.file) //nolint:gosec // p.file is the operator's --file; reading it is the command.
	if err != nil {
		if !p.readFailed {
			logger.WarnContext(ctx, "cannot read policy file", "file", p.file, "error", err)
			p.readFailed = true
		}
		p.pending = ""
		return nil, "", false
	}
	p.readFailed = false

	digest := policyDigest(raw)
	switch {
	case digest == p.last:
		// Already graded. An editor that rewrote identical bytes changed
		// nothing worth re-running.
		p.pending = digest
		return nil, "", false
	case digest != p.pending:
		// Seen once, not yet confirmed. Requiring two identical polls is both
		// the quiet period and the guard against grading a half-written file.
		p.pending = digest
		return nil, "", false
	}

	// Stable and new. Recording it before the caller evaluates is what makes an
	// unparseable save log once instead of every tick until it is repaired.
	p.last = digest
	return raw, digest, true
}

type validatedSnapshot struct {
	raw    []byte
	digest string
	local  *localTestComponent
}

type validationCompletion struct {
	snapshot   validatedSnapshot
	validation tailapi.ValidationResult
	err        error
}

//nolint:gocognit // Scheduler coordinates cancellation, coalescing, supersession, and emission.
func watchValidatedTests(
	ctx context.Context,
	opts options,
	testOpts testOptions,
	logger *slog.Logger,
	emitter *streamEmitter,
	client *tailscale.Client,
) error {
	seed, err := os.ReadFile(opts.file)
	if err != nil {
		return usagef("could not read policy for watch: %v", err)
	}
	logger.InfoContext(
		ctx, "watching policy file with server validation",
		"file", opts.file, "interval", testOpts.interval,
	)
	poller := newStablePolicyPoller(opts.file, seed)
	var active, queued *validatedSnapshot
	var activeSuperseded bool
	var cancel context.CancelFunc
	// One buffer slot is sufficient only because start is unreachable while a
	// request is in flight: it runs under active == nil, or after a completion
	// has already been drained. That invariant is also what makes the bare
	// return on ctx.Done safe — the abandoned goroutine's send lands in the
	// free slot and it exits. A third start site would leak a goroutine per
	// save with nothing here to catch it.
	completed := make(chan validationCompletion, 1)
	start := func(snapshot validatedSnapshot) {
		requestCtx, requestCancel := context.WithCancel(ctx) //nolint:gosec // Retained and called later.
		cancel, active = requestCancel, &snapshot
		go func() {
			validation, validationErr := tailapi.ValidatePolicy(requestCtx, client, snapshot.raw)
			validationErr = tailapi.WrapOAuthError(
				validationErr, tailapi.ScopePolicyFileRead, opts.oauthClientID, opts.oauthClientSecret)
			completed <- validationCompletion{snapshot, validation, validationErr}
		}()
	}
	emitSuperseded := func(snapshot validatedSnapshot) error {
		return emitter.emit(compositeTestResult(opts, snapshot, serverTestComponent{Status: serverSuperseded}))
	}
	ticker := time.NewTicker(testOpts.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if cancel != nil {
				cancel()
			}
			return nil
		case completion := <-completed:
			// A cancelled request completes with a transport error that names
			// the cancellation, not a verdict. Select picks uniformly when both
			// this and ctx.Done() are ready — which they are whenever the
			// interrupt lands while the loop is busy evaluating locally — so
			// without this guard Ctrl-C exits 2 with a synthetic "unavailable"
			// roughly half the time instead of exiting 0.
			if ctx.Err() != nil {
				return nil
			}
			if active == nil || completion.snapshot.digest != active.digest {
				continue
			}
			wasSuperseded := activeSuperseded
			active, cancel, activeSuperseded = nil, nil, false
			if wasSuperseded {
				if queued != nil {
					next := *queued
					queued = nil
					start(next)
				}
				continue
			}
			server := serverTestComponentFrom(completion.validation, completion.err)
			// Warnings are verdict data and a stderr event both, exactly as in
			// validate and plan. A snapshot the server accepts with warnings is
			// otherwise silent on stderr, which is the one channel an author
			// watching a second terminal is not reading as JSON.
			logValidationWarnings(ctx, logger, completion.validation)
			if err = emitter.emit(compositeTestResult(opts, completion.snapshot, server)); err != nil {
				return usagef("could not write watch output: %v", err)
			}
			if server.Status == serverUnavailable {
				return usagef("server validation unavailable: %s", server.Message)
			}
			if queued != nil {
				next := *queued
				queued = nil
				start(next)
			}
		case <-ticker.C:
			raw, digest, stable := poller.poll(ctx, logger)
			if !stable {
				continue
			}
			// policy_digest is a provenance claim, not a label: the local
			// evaluation and the POST body below both read raw, the same slice
			// poll hashed. No copy is needed to keep them identical because
			// poll hands back a slice nothing else retains.
			snapshot := validatedSnapshot{raw, digest, evaluateLocalComponent(ctx, opts, raw, logger)}
			if active == nil {
				start(snapshot)
				continue
			}
			if queued != nil {
				if err = emitSuperseded(*queued); err != nil {
					return usagef("could not write watch output: %v", err)
				}
			}
			queued = &snapshot
			if activeSuperseded {
				continue
			}
			activeSuperseded = true
			if err = emitSuperseded(*active); err != nil {
				return usagef("could not write watch output: %v", err)
			}
			cancel()
		}
	}
}

func evaluateLocalComponent(ctx context.Context, opts options, raw []byte, logger *slog.Logger) *localTestComponent {
	res, err := evaluatePolicyTestBytes(ctx, opts, raw, logger)
	if res == nil {
		message := "local evaluation failed"
		if err != nil {
			message = err.Error()
		}
		// Unlike plain watch, which emits nothing for a policy that will not
		// load, this path still submits the bytes: a server that accepts what
		// the local evaluator cannot read is the schema-drift evidence the mode
		// exists to surface. The stderr warning stays either way, so degrading
		// to input_error never hides why the evaluator gave up.
		logger.WarnContext(ctx, "policy file did not produce a local verdict",
			"file", opts.file, "error", err)
		return &localTestComponent{Status: localInputError, Message: message, Assertions: []aclpolicy.AssertionResult{}}
	}
	assertions := []aclpolicy.AssertionResult{}
	if res.Assertions != nil {
		assertions = *res.Assertions
	}
	return &localTestComponent{
		Status: res.Status, Message: res.Message, Assertions: assertions, Skipped: res.Skipped,
		SSHTestsSkipped: res.SSHTestsSkipped, Summary: res.TestSummary,
	}
}

func serverTestComponentFrom(validation tailapi.ValidationResult, err error) serverTestComponent {
	server := serverTestComponent{Validation: &validation}
	switch tailapi.ClassifyValidation(err) {
	case tailapi.ValidationClean:
		server.Status = serverClean
	case tailapi.ValidationRejected:
		server.Status = serverRejected
	case tailapi.ValidationIndeterminate:
		server.Status = serverIndeterminate
	case tailapi.ValidationUnavailable, tailapi.ValidationNotAttempted:
		server.Status, server.Unavailable = serverUnavailable, unavailableClass(err)
		server.Validation = nil
	}
	if err != nil {
		server.Message = err.Error()
	}
	if unavailable, ok := errors.AsType[*tailapi.ValidationUnavailableError](err); ok {
		server.HTTPStatus = unavailable.Status
		server.RetryAfter = unavailable.RetryAfter
	}
	return server
}

func unavailableClass(err error) string {
	var unavailable *tailapi.ValidationUnavailableError
	if !errors.As(err, &unavailable) {
		return unavailableResponse
	}
	switch unavailable.Status {
	case http.StatusUnauthorized:
		return unavailableAuthentication
	case http.StatusForbidden:
		return unavailableAuthorization
	case http.StatusTooManyRequests:
		return unavailableRateLimited
	case 0:
		// No status means the request never reached the control plane, so
		// rendering one would invent an answer it never gave.
		return unavailableTransport
	default:
		return unavailableResponse
	}
}

// compositeTestResult folds the two component verdicts into one envelope. The
// default arm covers serverIndeterminate as well as serverUnavailable, and that
// is deliberate rather than an omission: agreement's vocabulary has no
// indeterminate member because it reports whether the two halves *agree*, and
// there is nothing to agree with until the server proves acceptance or
// rejection. server.status keeps the distinction between "answered
// unreadably" and "never answered" for anyone who needs it.
func compositeTestResult(opts options, snapshot validatedSnapshot, server serverTestComponent) *result {
	status, agreement := statusIndeterminate, agreementUnavailable
	switch server.Status {
	case serverRejected:
		status = statusFailed
		switch snapshot.local.Status {
		case statusOK:
			agreement = agreementDisagree
		case statusFailed:
			agreement = agreementAgree
		default:
			agreement = agreementLocalGap
		}
	case serverClean:
		switch snapshot.local.Status {
		case statusOK:
			status, agreement = statusOK, agreementAgree
		case statusFailed:
			agreement = agreementDisagree
		default:
			agreement = agreementLocalGap
		}
	case serverSuperseded:
		agreement = agreementSuperseded
	}
	message := fmt.Sprintf(
		"local %s; server %s (%s)", snapshot.local.Status, server.Status, agreement,
	)
	res := newResult(cmdTest, status, message)
	res.File, res.PolicyDigest, res.Local, res.Server, res.Agreement = opts.file, snapshot.digest, snapshot.local, &server, agreement
	// Every record in this stream came from a credentialed request, so an audit
	// over the NDJSON can tell "API key" from "field not implemented here".
	res.Authentication = authenticationName(opts)
	return res
}

// policyDigest content-addresses policy bytes. One value does three jobs: change
// detection, the two-poll debounce, and the correlator on each streamed record.
func policyDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// evaluatePolicyTests reads opts.file and grades its assertions.
func evaluatePolicyTests(ctx context.Context, opts options, logger *slog.Logger) (*result, error) {
	raw, err := aclpolicy.ReadRaw(opts.file)
	if err != nil {
		return nil, usagef("could not load policy tests: %v", err)
	}
	return evaluatePolicyTestBytes(ctx, opts, raw, logger)
}

// evaluatePolicyTestBytes is the half watch reuses: it grades bytes the caller
// already read, so a watch run's reported digest names exactly what it graded.
// A nil result means no verdict exists — the contract watchTests keys on.
func evaluatePolicyTestBytes(
	ctx context.Context,
	opts options,
	raw []byte,
	logger *slog.Logger,
) (*result, error) {
	path := opts.file
	policy, err := aclpolicy.LoadBytes(path, raw)
	if err != nil {
		return nil, usagef("could not load policy tests: %v", err)
	}
	var roster map[string]tailscale.UserRole
	if opts.roster != "" {
		roster, err = loadRoster(opts.roster)
		if err != nil {
			return nil, err
		}
	}
	report, err := aclpolicy.EvaluateTests(
		&policy.ACL,
		aclpolicy.TestOptions{Strict: opts.strict, Roster: roster},
	)
	if err != nil {
		return nil, usagef("could not evaluate policy tests: %v", err)
	}
	// A skipped rule might have matched if understood. Warn without -verbose:
	// this is exactly the collection defect the AX conventions forbid
	// swallowing, even when field-scoped narrowing settles every assertion.
	for _, skip := range report.Skipped {
		logger.WarnContext(ctx, "skipping unparseable policy rule", "rule", skip.Rule,
			"value", skip.Value, "reason", skip.Reason)
	}
	// sshTests are loaded so typed edits preserve them, but this evaluator is
	// network-only. Warn for the same reason as the skipped rules above: a run
	// reporting "0 failed" must never imply assertions it never evaluated.
	if len(policy.SSHTests) != 0 {
		logger.WarnContext(ctx, "sshTests are preserved but not evaluated",
			"ssh_tests", len(policy.SSHTests))
	}
	for _, assertion := range report.Assertions {
		for _, decision := range assertion.Trace {
			logger.DebugContext(
				ctx,
				"policy test decision",
				"assertion",
				assertion.ID,
				"decision",
				decision,
			)
		}
	}

	status := statusOK
	message := fmt.Sprintf(
		"%d assertions: %d passed, %d failed",
		report.Summary.Total,
		report.Summary.Passed,
		report.Summary.Failed,
	)
	if report.Summary.Indeterminate != 0 {
		message += fmt.Sprintf(", %d indeterminate", report.Summary.Indeterminate)
	}
	if report.Summary.Total == 0 {
		message = fmt.Sprintf("no policy tests declared in %s", path)
	}
	// Without this the zero-network-test message reads "no policy tests
	// declared" for a policy whose only assertions are sshTests, which is the
	// opposite of true.
	if sshTests := len(policy.SSHTests); sshTests != 0 {
		message += fmt.Sprintf(" (%d sshTests preserved but not evaluated)", sshTests)
	}
	res := newResult(cmdTest, status, message)
	res.File = path
	res.Assertions = &report.Assertions
	res.Skipped = report.Skipped
	res.SSHTestsSkipped = len(policy.SSHTests)
	res.TestSummary = &report.Summary
	// A real disagreement outranks an unsettled one: a failing assertion is a
	// definite finding, so it decides the exit code even when another assertion
	// could not be evaluated.
	if report.Summary.Failed != 0 {
		res.Status = statusFailed
		return res, errAssertionsFailed
	}
	if report.Summary.Indeterminate != 0 {
		res.Status = statusIndeterminate
		switch opts.indeterminate.String() {
		case indeterminateFail:
			return res, errors.New("one or more policy assertions were indeterminate")
		case indeterminateIgnore:
			return res, nil
		default:
			return res, errReachabilityIndeterminate
		}
	}
	return res, nil
}

func runCheck(
	ctx context.Context,
	opts options,
	source, target string,
	protocol aclpolicy.Protocol,
	postureAttrs map[string]any,
	postureAttrsComplete bool,
	logger *slog.Logger,
) (*result, error) {
	policy, err := aclpolicy.Load(opts.file)
	if err != nil {
		return nil, usagef("could not load policy for check: %v", err)
	}
	var roster map[string]tailscale.UserRole
	if opts.roster != "" {
		roster, err = loadRoster(opts.roster)
		if err != nil {
			return nil, err
		}
	}
	decision, err := aclpolicy.EvaluateReachability(
		&policy.ACL,
		source,
		target,
		aclpolicy.ReachabilityOptions{
			Strict:               opts.strict,
			Protocol:             protocol,
			Roster:               roster,
			PostureAttrs:         postureAttrs,
			PostureAttrsComplete: postureAttrsComplete,
		},
	)
	if err != nil {
		return nil, usagef("could not evaluate reachability: %v", err)
	}
	for _, skip := range decision.Skipped {
		logger.WarnContext(ctx, "skipping unparseable policy rule", "rule", skip.Rule,
			"value", skip.Value, "reason", skip.Reason)
	}
	for _, trace := range decision.Trace {
		logger.DebugContext(ctx, "reachability decision", "decision", trace)
	}

	res := newCheckResult(opts.file, decision)
	switch decision.Access {
	case aclpolicy.AccessAllow:
		return res, nil
	case aclpolicy.AccessIndeterminate:
		return res, errReachabilityIndeterminate
	case aclpolicy.AccessDeny:
		return res, errReachabilityDenied
	default:
		return res, errReachabilityDenied
	}
}

// resolveCheckTarget validates check's flags and folds an optional --port into
// --dst, producing the source/target/protocol EvaluateReachability expects.
func resolveCheckTarget(
	source, destination string,
	portSet bool,
	port int,
	protocolRaw string,
) (string, string, aclpolicy.Protocol, error) {
	sourceValue := strings.TrimSpace(source)
	destinationValue := strings.TrimSpace(destination)
	if sourceValue == "" || destinationValue == "" {
		return "", "", "", usagef("check requires --src and --dst")
	}
	protocolValue := aclpolicy.Protocol(strings.ToLower(strings.TrimSpace(protocolRaw)))
	switch protocolValue {
	case aclpolicy.ProtocolAny, aclpolicy.ProtocolTCP, aclpolicy.ProtocolUDP, aclpolicy.ProtocolSCTP:
	default:
		return "", "", "", usagef(
			"unknown --proto %q; want %s, %s, %s, or %s",
			protocolRaw,
			aclpolicy.ProtocolTCP,
			aclpolicy.ProtocolUDP,
			aclpolicy.ProtocolSCTP,
			aclpolicy.ProtocolAny,
		)
	}
	if portSet && (port < 0 || port > 65535) {
		return "", "", "", usagef("--port %d is out of range; want 0-65535", port)
	}

	target := destinationValue
	if portSet {
		normalizedDestination, err := checkDestinationWithoutPort(destinationValue)
		if err != nil {
			return "", "", "", err
		}
		// Brackets make selectors containing colons (tags and IPv6 addresses)
		// unambiguous to the shared host:port parser.
		target = fmt.Sprintf("[%s]:%d", normalizedDestination, port)
	}
	return sourceValue, target, protocolValue, nil
}

func checkDestinationWithoutPort(value string) (string, error) {
	original := value
	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		if len(value) < 3 || value[0] != '[' || value[len(value)-1] != ']' {
			return "", usagef("--dst %q has malformed brackets", original)
		}
		value = value[1 : len(value)-1]
		if value == "" || strings.ContainsAny(value, "[]") {
			return "", usagef("--dst %q has malformed brackets", original)
		}
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return value, nil
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return value, nil
	}

	separator := strings.LastIndexByte(value, ':')
	if separator < 0 {
		return value, nil
	}
	if separator == 0 || separator == len(value)-1 {
		return "", usagef("--dst %q is malformed", value)
	}
	if isDecimal(value[separator+1:]) {
		return "", usagef("--dst %q already includes a port; do not also use --port", value)
	}
	if strings.Contains(value[:separator], ":") {
		return "", usagef("--dst %q is ambiguous; bracket IPv6 addresses and specify the port once", value)
	}
	return value, nil
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func newCheckResult(path string, decision aclpolicy.ReachabilityResult) *result {
	verdict, status := verdictNotReachable, statusFailed
	switch decision.Access {
	case aclpolicy.AccessAllow:
		verdict, status = verdictReachable, statusOK
	case aclpolicy.AccessIndeterminate:
		verdict, status = verdictIndeterminate, statusIndeterminate
	case aclpolicy.AccessDeny:
	}
	message := fmt.Sprintf(
		"%s: %s -> %s:%d (%s)",
		verdict,
		decision.Source,
		decision.Destination,
		decision.Port,
		decision.Evidence,
	)
	res := newResult(cmdCheck, status, message)
	res.File = path
	res.Access = decision.Access
	res.Protocol = decision.Protocol
	// Already nil for an indeterminate answer; see aclpolicy.ReachabilityResult.
	res.Allowed = decision.Allowed
	res.Source = decision.Source
	res.Destination = decision.Destination
	res.Port = &decision.Port
	res.Evidence = decision.Evidence
	res.Trace = decision.Trace
	res.Skipped = decision.Skipped
	if decision.Rule != nil {
		index := decision.Rule.Index
		switch decision.Rule.Kind {
		case aclpolicy.RuleGrant:
			res.GrantIndex = &index
		case aclpolicy.RuleACL:
			res.ACLIndex = &index
		}
	}
	return res
}

func runLint(
	ctx context.Context,
	opts options,
	lintOpts aclpolicy.LintOptions,
	threshold aclpolicy.LintSeverity,
	severityExplicit bool,
	configPath string,
	online bool,
	httpClient *http.Client,
	apiURL string,
	logger *slog.Logger,
) (*result, error) {
	if configPath != "" {
		config, err := aclpolicy.LoadLintConfig(configPath)
		if err != nil {
			return nil, usagef("could not load lint config: %v", err)
		}
		lintOpts.AllowBroadDestinations = config.Checks.BroadRuleUntested.AllowBroad
	}
	policy, err := aclpolicy.Load(opts.file)
	if err != nil {
		return nil, usagef("could not load policy for lint: %v", err)
	}
	report, err := aclpolicy.EvaluatePolicyLint(policy, lintOpts)
	if err != nil {
		return nil, usagef("could not lint policy: %v", err)
	}

	// A failed online check must not discard the offline report, which is
	// already complete: returning a nil result here left stdout empty, so an
	// operator whose token lacks services-read got exit 2 and no findings at
	// all, and could not tell a broken policy from a broken token without
	// re-running. The error is still returned, so exitCode maps the collection
	// failure to 2 rather than reporting the policy failed on a read that never
	// happened.
	var onlineErr error
	if online {
		onlineErr = lintOnline(ctx, opts, httpClient, apiURL, &policy.ACL, &report, logger)
	}

	for _, finding := range report.Findings {
		for _, decision := range finding.Trace {
			logger.DebugContext(ctx, "lint decision",
				"finding", finding.ID, "rule", finding.Rule, "decision", decision)
		}
	}

	res := newLintResult(opts.file, report, threshold, severityExplicit)
	// Only the online path authenticates; a plain lint reads no credential, so
	// claiming one would misreport an entirely offline run.
	if online {
		res.Authentication = authenticationName(opts)
	}
	// A collection failure outranks the policy verdict: the report is rendered
	// either way, but the exit code must say "could not check" rather than
	// "policy is clean".
	if onlineErr != nil {
		return res, onlineErr
	}
	// The gate always reads the whole report. When -severity was explicit, the
	// human filter uses the same floor; when it was omitted, the human view shows
	// everything but this default warn floor still controls the exit status.
	if report.CountAtLeast(threshold) > 0 {
		res.Status = statusFailed
		return res, errLintFindings
	}
	return res, nil
}

// lintOnline augments an offline lint report with control-plane checks that a
// static run cannot make. It builds the API client directly rather than through
// apiClient, which hard-fails exit 2 on missing credentials: lint's online
// validation is opt-in and best-effort, so absent credentials degrade to a
// logged skip (never swallowed silently, per AX convention 5) and the offline
// findings stand. A control plane that never answered is a collection failure,
// surfaced so exitCode maps it to exit 2 rather than reporting the policy failed
// on a read that never happened.
func lintOnline(
	ctx context.Context,
	opts options,
	httpClient *http.Client,
	apiURL string,
	policy *tailscale.ACL,
	report *aclpolicy.LintReport,
	logger *slog.Logger,
) error {
	if opts.tailnet == "" || !hasCredentials(opts) {
		logger.WarnContext(ctx, "skipping online validation: missing credentials",
			"tailnet_set", opts.tailnet != "", "credentials_set", hasCredentials(opts))
		return nil
	}
	client, err := apiClient(opts, httpClient, apiURL, tailapi.ScopePolicyFileRead)
	if err != nil {
		return err
	}
	serviceRefs := aclpolicy.ServiceDestinationRefs(policy)
	serviceExists := make(map[string]bool, len(serviceRefs))
	servicesReadable := true
	// lookupClient is built via tscli rather than apiClient/tailapi.NewClient
	// — scoped to this one call as the proof of concept recorded in
	// CONTEXT.md/ROADMAP.md. Every other client in this command (including
	// collectSCIMSyncWarnings below) still goes through tailapi.NewClient.
	var lookupClient *tailscale.Client
	if len(serviceRefs) > 0 {
		lookupClient, err = tscliServiceLookupClient(opts, apiURL)
		if err != nil {
			return err
		}
	}
	for _, ref := range serviceRefs {
		// tscli's client builds its own http.Client with no Timeout set, so
		// the httpTimeout bound that apiClient's httpClient would have applied
		// is reapplied here through the context.
		lookupCtx, cancel := context.WithTimeout(ctx, httpTimeout)
		lookup, lookupErr := tailapi.LookupService(lookupCtx, lookupClient, ref.Selector)
		cancel()
		// RedactSecret rather than WrapOAuthError: this call reads
		// vip-services, and Tailscale publishes no OAuth scope covering that
		// endpoint. Naming the policy-file scope here would blame a scope the
		// token already holds and send the operator to re-grant it.
		lookupErr = tailapi.RedactSecret(lookupErr, opts.oauthClientSecret)
		if lookupErr != nil {
			if opts.oauthClientID == "" || !tailapi.IsForbidden(lookupErr) {
				return lookupErr
			}
			// A scoped OAuth client cannot read vip-services at all, so
			// svc-unknown degrades to absent rather than failing the run —
			// the rule #119 set for a credential missing one read scope. The
			// SCIM-sync warnings below need only policy_file:read and stay
			// valid, as does every offline finding already in the report.
			logger.WarnContext(ctx,
				"skipping svc-unknown findings: the OAuth client cannot read vip-services",
				"service", ref.Selector, "error", lookupErr)
			servicesReadable = false
			break
		}
		serviceExists[ref.Selector] = lookup.Exists
	}
	// Add rather than a local append-and-count: the severity vocabulary belongs
	// to aclpolicy, and a copy of that switch out here would silently stop
	// summing to Total the day a severity is added.
	if servicesReadable {
		report.Add(aclpolicy.EvaluateServiceExistence(serviceRefs, serviceExists)...)
	}

	warnings, err := collectSCIMSyncWarnings(ctx, client, opts.file, opts.oauthClientSecret, logger)
	if err != nil {
		return err
	}
	report.Add(aclpolicy.EvaluateSCIMGroupSync(warnings)...)
	return nil
}

// collectSCIMSyncWarnings submits the policy to /acl/validate and returns the
// flat list of control-plane warning strings. There is no API to list synced
// groups, so a group referenced but not actually syncing from SCIM surfaces only
// here, as a validation warning. A control plane that never judged the policy
// (ValidationUnavailable) is a collection failure and is propagated so exitCode
// maps it to exit 2; every other validate outcome — including a policy the
// control plane rejects — is not lint's verdict to render, so it is logged at
// WARN and whatever warnings were collected (possibly none) are returned.
func collectSCIMSyncWarnings(
	ctx context.Context,
	client *tailscale.Client,
	path string,
	clientSecret string,
	logger *slog.Logger,
) ([]string, error) {
	result, err := tailapi.ValidateFile(ctx, client, path)
	// Redact before the error can be returned to realMain or handed to the
	// logger. This is the one control-plane call whose error reaches stderr
	// without passing through WrapOAuthError, and a token-endpoint failure
	// arrives here as an oauth2.RetrieveError whose text embeds the response
	// body — so "the secret never appears in output, logs, or errors" has to
	// hold per call site, not per command.
	err = tailapi.RedactSecret(err, clientSecret)
	if err != nil {
		// Judged() rather than == ValidationUnavailable: NotAttempted is the
		// other "the control plane never answered" outcome - an unreadable
		// policy file or a request that could not be built - and treating it
		// as a completed check reported the policy clean on a check that never
		// ran. Rejected and Indeterminate stay on the continue path, since
		// both carry usable warnings.
		if !tailapi.ClassifyValidation(err).Judged() {
			return nil, err
		}
		logger.WarnContext(ctx, "control-plane validation did not prove the policy clean; "+
			"reporting any SCIM-sync warnings it returned and continuing lint",
			"error", err)
	}
	warnings := make([]string, 0)
	for _, detail := range result.Warnings {
		warnings = append(warnings, detail.Warnings...)
	}
	return warnings, nil
}

// resolveLintOptions validates lint's --severity/--wildcard flags and folds the
// SCIM-group exemption controls (--strict-scim-groups, --scim-domains) into the
// resulting LintOptions.
func resolveLintOptions(
	severityRaw, wildcardRaw string,
	strictSCIMGroups bool,
	scimDomainsRaw stringListFlag,
) (aclpolicy.LintOptions, aclpolicy.LintSeverity, error) {
	threshold, ok := aclpolicy.ParseLintSeverity(severityRaw)
	if !ok {
		if strings.Contains(severityRaw, ",") {
			return aclpolicy.LintOptions{}, "", usagef(
				"-severity accepts one minimum, not a list; choose advice, info, warn, or error " +
					"(warn already includes error)",
			)
		}
		return aclpolicy.LintOptions{}, "", usagef(
			"unknown -severity %q; want advice, info, warn, or error",
			severityRaw,
		)
	}
	wildcardPolicy, ok := aclpolicy.ParseWildcardPolicy(wildcardRaw)
	if !ok {
		return aclpolicy.LintOptions{}, "", usagef("unknown -wildcard %q; want any-to-any, any, or off", wildcardRaw)
	}
	// Both checks below exist because the failure is silent and points the
	// wrong way: a request to narrow the exemption that quietly widens it, or
	// a carve-out that quietly does nothing.
	scimDomains := splitCommaList(scimDomainsRaw)
	if len(scimDomainsRaw) > 0 {
		if strictSCIMGroups {
			return aclpolicy.LintOptions{}, "", usagef(
				"-scim-domains has no effect with -strict-scim-groups, which errors on every SCIM group; " +
					"use -scim-domains alone to narrow the exemption",
			)
		}
		if len(scimDomains) == 0 {
			return aclpolicy.LintOptions{}, "", usagef(
				"-scim-domains resolved to no domains; an empty list would exempt every SCIM group " +
					"rather than none, so it is rejected instead of widening the exemption",
			)
		}
	}
	return aclpolicy.LintOptions{
		Wildcard:         wildcardPolicy,
		StrictSCIMGroups: strictSCIMGroups,
		SCIMDomains:      scimDomains,
	}, threshold, nil
}

// newLintResult keeps the complete report for the versioned JSON envelope. An
// explicit -severity applies to the human-summary count; an omitted flag shows
// the whole report while retaining warn as the failure threshold. The renderer
// applies the same presentation choice, and the classifier and machine contract
// retain everything they found (AX conventions 2 and 9).
func newLintResult(
	path string,
	report aclpolicy.LintReport,
	threshold aclpolicy.LintSeverity,
	severityExplicit bool,
) *result {
	findings := slices.Clone(report.Findings)
	reported := report.Summary.Total
	if severityExplicit {
		reported = report.CountAtLeast(threshold)
	}
	res := newResult(cmdLint, statusOK, lintMessage(path, report.Summary, reported, threshold))
	res.File = path
	res.Findings = &findings
	res.LintSummary = &report.Summary
	res.LintThreshold = string(threshold)
	res.LintSeverityExplicit = severityExplicit
	return res
}

// lintMessage states what was reported and, whenever the threshold withheld
// something, what it withheld. The failure mode it exists to prevent is a
// trailer reading as a clean policy when the policy was not clean and the
// threshold was merely high, so the whole-policy breakdown stays on the line
// and names the flag that reveals the rest.
func lintMessage(
	path string,
	summary aclpolicy.LintSummary,
	reported int,
	threshold aclpolicy.LintSeverity,
) string {
	var b strings.Builder
	for _, seg := range lintSummarySegments(path, summary, reported, threshold) {
		b.WriteString(seg.text)
	}
	return b.String()
}

// summarySegment is one span of the lint summary line: its literal text and the
// ANSI color that span carries (empty for none). Concatenating every segment's
// text reproduces the plain message byte for byte, which is what lets
// lintMessage (plain, into res.Message) and renderLintSummaryLine (colored)
// share one definition of the wording — the "colors match the output" contract.
type summarySegment struct {
	text  string
	color string
}

// lintSummarySegments splits the summary into colorable spans. Only the count
// tokens ("0 error", "33 warn", …) carry color; the lead-in, the separators,
// the withheld-findings clause, and the scim/svc reference tallies stay
// default. Both the total svc reference count and its online-checkable
// destination subset are named so the two sets cannot be mistaken for each
// other. The zero-total case has no counts to color, matching the plain wording
// exactly.
func lintSummarySegments(
	path string,
	summary aclpolicy.LintSummary,
	reported int,
	threshold aclpolicy.LintSeverity,
) []summarySegment {
	scim := refNote(summary.SCIMGroupRefs, "scim group reference", "scim group references") +
		refNote(summary.SvcRefs, "svc reference", "svc references") +
		refNote(
			summary.SvcDstRefs,
			"online-checkable svc destination reference",
			"online-checkable svc destination references",
		)
	if summary.Total == 0 {
		return []summarySegment{{text: fmt.Sprintf("no policy hygiene findings in %s%s", path, scim)}}
	}
	var segs []summarySegment
	switch reported {
	case summary.Total:
		segs = append(segs, summarySegment{
			text: fmt.Sprintf("%d %s: ", summary.Total, findingNoun(summary.Total)),
		})
	case 0:
		segs = append(segs, summarySegment{
			text: fmt.Sprintf("no findings at or above %s; %d total: ", threshold, summary.Total),
		})
	default:
		segs = append(segs, summarySegment{
			text: fmt.Sprintf(
				"%d %s at or above %s; %d total: ", reported, findingNoun(reported), threshold, summary.Total,
			),
		})
	}
	segs = append(segs, breakdownSegments(summary)...)
	if scim != "" {
		segs = append(segs, summarySegment{text: scim})
	}
	if reported != summary.Total {
		segs = append(segs, summarySegment{text: " (-severity advice shows/fails on all)"})
	}
	return segs
}

// breakdownSegments returns the whole-policy severity counts, each colored by
// its own severity so the breakdown reads at a glance.
func breakdownSegments(summary aclpolicy.LintSummary) []summarySegment {
	segs := []summarySegment{
		{text: fmt.Sprintf("%d error", summary.Error), color: countColor(aclpolicy.LintError, summary.Error)},
		{text: ", "},
		{text: fmt.Sprintf("%d warn", summary.Warn), color: countColor(aclpolicy.LintWarn, summary.Warn)},
		{text: ", "},
		{text: fmt.Sprintf("%d info", summary.Info), color: countColor(aclpolicy.LintInfo, summary.Info)},
	}
	if summary.Advice != 0 {
		segs = append(segs,
			summarySegment{text: ", "},
			summarySegment{
				text:  fmt.Sprintf("%d advice", summary.Advice),
				color: countColor(aclpolicy.LintAdvice, summary.Advice),
			},
		)
	}
	return segs
}

// renderLintSummaryLine writes the colored summary line. It is reached only when
// colorize is true and the result is a lint report; the plain path in render
// keeps printing res.Message so non-lint commands and no-color runs are
// untouched.
func renderLintSummaryLine(
	w io.Writer,
	path string,
	summary aclpolicy.LintSummary,
	reported int,
	threshold aclpolicy.LintSeverity,
) error {
	var b strings.Builder
	b.WriteString("tsacl: ")
	for _, seg := range lintSummarySegments(path, summary, reported, threshold) {
		b.WriteString(paint(true, seg.color, seg.text))
	}
	b.WriteString("\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// refNote renders a count of references the linter recognized but did not flag.
// They are not findings, so a semicolon keeps them out of the severity
// breakdown rather than reading as another bucket that fails to add up.
func refNote(count int, singular, plural string) string {
	if count == 0 {
		return ""
	}
	noun := plural
	if count == 1 {
		noun = singular
	}
	return fmt.Sprintf("; %d %s", count, noun)
}

func findingNoun(count int) string {
	if count == 1 {
		return "finding"
	}
	return "findings"
}

func runPlan(
	ctx context.Context,
	opts options,
	httpClient *http.Client,
	apiURL string,
	logger *slog.Logger,
) (*result, error) {
	client, err := apiClient(opts, httpClient, apiURL, tailapi.ScopePolicyFileRead)
	if err != nil {
		return nil, err
	}
	plan, err := tailapi.PlanFile(ctx, client, opts.file)
	err = tailapi.WrapOAuthError(err, tailapi.ScopePolicyFileRead, opts.oauthClientID, opts.oauthClientSecret)
	// Warnings the control plane did supply are reported even when a later step
	// fails, so a diagnostic already collected is never silently discarded.
	if plan != nil {
		logValidationWarnings(ctx, logger, plan.Validation)
	}
	if err != nil {
		status := validationEnvelopeStatus(err)
		if status == "" || plan == nil {
			return nil, err
		}
		message := fmt.Sprintf("plan validation failed for tailnet %s", opts.tailnet)
		if status == statusIndeterminate {
			message = fmt.Sprintf("plan validation is indeterminate for tailnet %s", opts.tailnet)
		}
		res := newResult(cmdPlan, status, message)
		res.File = opts.file
		res.Tailnet = opts.tailnet
		res.Authentication = authenticationName(opts)
		res.Validation = &plan.Validation
		return res, err
	}
	status, changeText := statusNoChanges, "no changes"
	if plan.Changed {
		status, changeText = statusChangesFound, "changes found"
	}
	message := fmt.Sprintf("plan valid; %s for tailnet %s", changeText, opts.tailnet)
	if plan.ETag != "" {
		message += fmt.Sprintf(" (ETag %s)", plan.ETag)
	}
	res := newResult(cmdPlan, status, message)
	res.File = opts.file
	res.Tailnet = opts.tailnet
	res.Authentication = authenticationName(opts)
	res.ETag = plan.ETag
	changed := plan.Changed
	res.Changed = &changed
	res.Validation = &plan.Validation
	if plan.Changed {
		res.Diff = plan.Diff
	}
	if err = recordObservedETag(ctx, opts.file, opts.tailnet, plan.ETag); err != nil {
		return nil, usagef("recording plan ETag: %v", err)
	}
	return res, nil
}

func runPull(
	ctx context.Context,
	opts options,
	force bool,
	httpClient *http.Client,
	apiURL string,
) (*result, error) {
	if !force {
		if _, err := os.Stat(opts.file); err == nil {
			return nil, usagef("refusing to overwrite existing policy file %s; use --force to replace it", opts.file)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, usagef("checking policy file %s: %v", opts.file, err)
		}
	}
	client, err := apiClient(opts, httpClient, apiURL, tailapi.ScopePolicyFileRead)
	if err != nil {
		return nil, err
	}
	policy, err := tailapi.FetchPolicy(ctx, client)
	err = tailapi.WrapOAuthError(err, tailapi.ScopePolicyFileRead, opts.oauthClientID, opts.oauthClientSecret)
	if err != nil {
		return nil, usageError{err}
	}
	// An empty body is a server fault, never a deployed policy. Writing it would
	// report success while destroying the local file --force was aimed at.
	if strings.TrimSpace(string(policy.HuJSON)) == "" {
		return nil, usagef("control plane returned an empty policy for tailnet %s; %s left unchanged",
			opts.tailnet, opts.file)
	}
	if err = aclpolicy.WriteRaw(opts.file, policy.HuJSON); err != nil {
		return nil, usagef("writing pulled policy to %s: %v", opts.file, err)
	}
	if err = recordObservedETag(ctx, opts.file, opts.tailnet, policy.ETag); err != nil {
		return nil, usagef("recording pulled ETag: %v", err)
	}
	message := fmt.Sprintf("pulled deployed policy for tailnet %s to %s", opts.tailnet, opts.file)
	if policy.ETag != "" {
		message += fmt.Sprintf(" (ETag %s)", policy.ETag)
	}
	res := newResult(cmdPull, statusOK, message)
	res.File = opts.file
	res.Tailnet = opts.tailnet
	res.Authentication = authenticationName(opts)
	res.ETag = policy.ETag
	return res, nil
}

func runUpload(
	ctx context.Context,
	opts options,
	ifMatchExplicit bool,
	acceptRemoteChanges bool,
	httpClient *http.Client,
	apiURL string,
) (*result, error) {
	if err := checkUploadFlags(opts, ifMatchExplicit, acceptRemoteChanges); err != nil {
		return nil, err
	}
	client, err := apiClient(opts, httpClient, apiURL, tailapi.ScopePolicyFile)
	if err != nil {
		return nil, err
	}
	if opts.ifMatch, err = resolveUploadETag(opts, ifMatchExplicit, acceptRemoteChanges); err != nil {
		return nil, err
	}
	uploaded, err := tailapi.UploadFile(ctx, client, opts.file, opts.ifMatch)
	err = tailapi.WrapOAuthError(err, tailapi.ScopePolicyFile, opts.oauthClientID, opts.oauthClientSecret)
	if err != nil {
		if isPreconditionFailed(err) {
			return nil, errors.New(staleUploadRemediation)
		}
		return nil, err
	}
	newETag := uploaded.ETag
	if newETag == "" {
		observed, fetchErr := tailapi.FetchPolicy(ctx, client)
		fetchErr = tailapi.WrapOAuthError(fetchErr, tailapi.ScopePolicyFile, opts.oauthClientID, opts.oauthClientSecret)
		switch {
		case fetchErr != nil:
			return nil, fmt.Errorf(
				"upload succeeded but its new ETag could not be recorded: %w; run plan before uploading again",
				fetchErr,
			)
		case observed.ETag == "":
			return nil, errors.New(
				"upload succeeded but the control plane returned no new ETag; run plan before uploading again",
			)
		case !bytes.Equal(observed.HuJSON, uploaded.HuJSON):
			return nil, errors.New(
				"upload succeeded, but the deployed policy changed before its new ETag could be recorded; " +
					"run pull and reconcile before uploading again",
			)
		default:
			newETag = observed.ETag
		}
	}
	if err = recordObservedETag(ctx, opts.file, opts.tailnet, newETag); err != nil {
		return nil, fmt.Errorf(
			"upload succeeded but its new ETag could not be recorded: %w; run plan before uploading again",
			err,
		)
	}
	message := fmt.Sprintf("uploaded %s to tailnet %s", opts.file, opts.tailnet)
	if acceptRemoteChanges {
		message += " (--accept-remote-changes used; upload sent no If-Match)"
	}
	res := newResult(cmdUpload, statusOK, message)
	res.File = opts.file
	res.Tailnet = opts.tailnet
	res.Authentication = authenticationName(opts)
	res.ETag = newETag
	res.AcceptedRemoteChanges = acceptRemoteChanges
	return res, nil
}

func checkUploadFlags(opts options, ifMatchExplicit, acceptRemoteChanges bool) error {
	if ifMatchExplicit && acceptRemoteChanges {
		return usagef("--if-match and --accept-remote-changes are mutually exclusive")
	}
	if ifMatchExplicit && strings.TrimSpace(opts.ifMatch) == "" {
		return usagef("--if-match requires a non-empty ETag; use --accept-remote-changes to upload without one")
	}
	return nil
}

// resolveUploadETag returns the If-Match value an upload will send: the
// explicit one, none when remote changes are accepted, otherwise the ETag the
// last plan or pull recorded.
func resolveUploadETag(opts options, ifMatchExplicit, acceptRemoteChanges bool) (string, error) {
	if ifMatchExplicit || acceptRemoteChanges {
		return opts.ifMatch, nil
	}
	observedETag, err := observedstate.Read(opts.file, opts.tailnet)
	if err != nil {
		return "", usagef(
			"refusing to upload without a recorded ETag for tailnet %s: %v; "+
				"run plan or pull to observe the deployed policy, supply --if-match, or explicitly opt out with --accept-remote-changes",
			opts.tailnet, err,
		)
	}
	return observedETag, nil
}

// recordObservedETag persists the observed ETag unless dry-run is active. The
// audit lines are suppressed: the surrounding command already audits its write.
func recordObservedETag(ctx context.Context, file, tailnet, etag string) error {
	_, err := ax.GuardWithAudit(ax.WithAudit(ctx, false), "record observed ETag",
		func(context.Context) error { return observedstate.Record(file, tailnet, etag) })
	return err
}

func isPreconditionFailed(err error) bool {
	var apiError tailscale.APIError
	return errors.As(err, &apiError) && apiError.Status == http.StatusPreconditionFailed
}

const staleUploadRemediation = "deployed policy changed since the last observation; upload refused. " +
	"Pull the deployed policy to a separate file with `tsacl --file <remote-policy.hujson> pull`, " +
	"then reconcile through the comment-preserving pair merge " +
	"`tsacl merge --base <remote-policy.hujson> --add <local-change-snippet.hujson> --out <reconciled-policy.hujson>`. " +
	"Review the result and run `tsacl --file <reconciled-policy.hujson> plan` before retrying. " +
	"Do not use `tsacl merge --dir` for this reconciliation; the directory merge standardizes away HuJSON comments"

func apiClient(opts options, httpClient *http.Client, apiURL, requiredScope string) (*tailscale.Client, error) {
	if opts.tailnet == "" {
		return nil, usagef("--tailnet or TAILSCALE_TAILNET is required")
	}
	if opts.apiKey == "" && opts.oauthClientID == "" && opts.oauthClientSecret == "" {
		return nil, usagef("--api-key or --oauth-client-id/--oauth-client-secret credentials are required")
	}
	client, err := tailapi.NewClient(tailapi.Config{
		APIKey:            opts.apiKey,
		OAuthClientID:     opts.oauthClientID,
		OAuthClientSecret: opts.oauthClientSecret,
		OAuthScopes:       []string{requiredScope},
		Tailnet:           opts.tailnet,
		BaseURL:           apiURL,
		HTTP:              httpClient,
	})
	if err != nil {
		return nil, usageError{err}
	}
	return client, nil
}

// tscliServiceLookupClientMu serializes access to viper's process-global
// config: tscli.New (github.com/jaxxstorm/tscli/pkg/tscli) reads its
// configuration from viper rather than taking an explicit Config the way
// tailapi.NewClient does, and this repo's tests run in parallel. The mutex
// scopes the race to "one goroutine sets viper, then reads it back into a
// client" — the *tailscale.Client returned already carries everything it
// read, so it needs no further synchronization once built.
//
//nolint:gochecknoglobals // guards access to tscli's process-global viper config, not application state
var tscliServiceLookupClientMu sync.Mutex

// tscliServiceLookupClient builds the same official v2 API client apiClient
// does, but through github.com/jaxxstorm/tscli's constructor instead of
// tailapi.NewClient — the one-call proof of concept recorded in
// CONTEXT.md/ROADMAP.md ("tail-ipam" future-vision entry). It is scoped to
// exactly the LookupService call in lintOnline.
func tscliServiceLookupClient(opts options, apiURL string) (*tailscale.Client, error) {
	tscliServiceLookupClientMu.Lock()
	defer tscliServiceLookupClientMu.Unlock()

	viper.Set("tailnet", opts.tailnet)
	viper.Set("api-key", opts.apiKey)
	viper.Set("oauth-client-id", opts.oauthClientID)
	viper.Set("oauth-client-secret", opts.oauthClientSecret)
	viper.Set("base-url", apiURL)

	// tscli derives its default User-Agent from the git state of the working
	// directory, which would send the policy repo's HEAD to the API.
	viper.Set("user-agent", toolName+"/"+version)

	client, err := tscli.New()
	viper.Set("oauth-client-secret", "")
	viper.Set("api-key", "")
	if err != nil {
		redactedErr := tailapi.RedactSecret(
			fmt.Errorf("constructing tscli-backed client: %w", err),
			opts.oauthClientSecret,
		)
		return nil, redactedErr
	}
	return client, nil
}

func authenticationName(opts options) string {
	if opts.oauthClientID != "" && opts.oauthClientSecret != "" {
		return "oauth_client_credentials"
	}
	return ""
}

func hasCredentials(opts options) bool {
	return opts.apiKey != "" || opts.oauthClientID != "" || opts.oauthClientSecret != ""
}

// resolveCredentials fills each unset credential from the environment, with one
// rule: an explicitly supplied class suppresses the *other* class's environment
// fallback. Two credentials are only genuinely ambiguous when the operator
// supplied both; an ambient TAILSCALE_API_KEY vetoing an explicit
// --oauth-client-id is not a safety property, it is a dead end, because a
// process cannot unset its own environment and this repo's own
// scripts/tailnet-audit-report.sh injects that variable. Two explicit classes
// still conflict, and NewClient rejects them before any request is made.
func resolveCredentials(opts *options, getenv func(string) string, apiKeyExplicit, oauthExplicit bool) {
	if !oauthExplicit && opts.apiKey == "" {
		opts.apiKey = getenv("TAILSCALE_API_KEY")
	}
	if apiKeyExplicit {
		return
	}
	if opts.oauthClientID == "" {
		opts.oauthClientID = getenv("TAILSCALE_OAUTH_CLIENT_ID")
	}
	if opts.oauthClientSecret == "" {
		opts.oauthClientSecret = getenv("TAILSCALE_OAUTH_CLIENT_SECRET")
	}
}

type schemaFlag struct {
	Name    string `json:"name"`
	Usage   string `json:"usage"`
	Default string `json:"default"`
}

type schemaCommand struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	Usage   string `json:"usage"`
}

type schemaCapabilities struct {
	TypedEdits schemaTypedEditCapability `json:"typed_edits"`
}

type schemaTypedEditCapability struct {
	Formats           []string `json:"formats"`
	PreservesComments bool     `json:"preserves_comments"`
	AuthorsComments   bool     `json:"authors_comments"`
}

// commandCatalog is the single source of truth for the command list, shared by
// usage() and the -schema document so a human and an agent see the same set.
//
//nolint:funlen // the catalog intentionally keeps command metadata in one source of truth.
func commandCatalog() []schemaCommand {
	return []schemaCommand{
		{cmdInit, "Initialize an empty policy for typed authoring", cmdInit},
		{
			commandGrantAdd,
			"Append a grant to the policy",
			"grant add --src SRC --dst DST --ip PROTO:PORT [--src-posture posture:NAME] [--comment TEXT]",
		},
		{commandGrantRemove, "Remove a grant by zero-based index", "grant remove --index N"},
		{
			commandGroupAdd,
			"Add login or autogroup members to a group; idempotent and merges into an existing group",
			"group add --name group:NAME --member LOGIN [--member LOGIN ...] [--comment TEXT]",
		},
		{
			commandGroupRemove,
			"Remove a group definition; referenced groups require --force",
			"group remove --name group:NAME [--force]",
		},
		{
			commandIPSetAdd,
			"Add members to an ipset (CIDR, address, range, host:, ipset:, or add/remove operations); " +
				"a remove requires every member to be an explicit operation; idempotent and merges into an existing ipset",
			"ipset add --name ipset:NAME (--member MEMBER | --cidr CIDR) [--member MEMBER ...] [--cidr CIDR ...] " +
				"[--comment TEXT]",
		},
		{
			commandIPSetRemove,
			"Remove an ipset definition; referenced ipsets require --force",
			"ipset remove --name ipset:NAME [--force]",
		},
		{
			commandSSHAdd,
			"Add an SSH rule; selector order is ignored, duplicate rules are a no-op, and check without a period differs from check with one",
			"ssh add --action accept|check --src SRC --dst DST --user USER [--check-period DURATION|always] [--recorder DST] [--enforce-recorder] [--comment TEXT]",
		},
		{
			commandSSHRemove,
			"Remove an SSH rule by semantic identity or zero-based index; check without a period differs from check with one",
			"ssh remove (--index N | --action accept|check --src SRC --dst DST --user USER [--check-period DURATION|always] [--recorder DST] [--enforce-recorder])",
		},
		{
			commandNodeAttrAdd,
			"Add attributes or IP pools to a target set; target order is ignored and matching entries are merged",
			"nodeattr add --target SELECTOR [--target SELECTOR ...] (--attr NAME [--attr NAME ...] | --ip-pool CIDR [--ip-pool CIDR ...]) [--comment TEXT] [--overwrite-comment]",
		},
		{
			commandNodeAttrRemove,
			"Remove attributes or IP pools from every matching target entry, pruning entries left empty, or remove one by index",
			"nodeattr remove (--index N | --target SELECTOR [--target SELECTOR ...] (--attr NAME [--attr NAME ...] | --ip-pool CIDR [--ip-pool CIDR ...]))",
		},
		{commandTagOwnerAdd, "Add an owner to a tag", "tag-owner add TAG OWNER [--comment TEXT]"},
		{commandHostSet, "Set a host alias to an address", "host set NAME ADDRESS [--comment TEXT]"},
		{
			commandPostureSet,
			"Add or replace a posture's expression list",
			"posture set NAME EXPR [EXPR ...] [--comment TEXT]",
		},
		{commandPostureRemove, "Remove a posture definition", "posture remove NAME"},
		{
			commandAutoApproverAdd,
			"Add auto-approvers for a route or the exit-node list; idempotent and merges into an existing route",
			"auto-approver add (--route CIDR | --exit-node) --approver SELECTOR [--approver SELECTOR ...] [--comment TEXT]",
		},
		{
			commandAutoApproverRemove,
			"Remove auto-approvers; an emptied route key or exitNode member is pruned rather than " +
				"left as an empty list",
			"auto-approver remove (--route CIDR | --exit-node) --approver SELECTOR [--approver SELECTOR ...]",
		},
		{
			commandExternalTailnetAdd,
			"Add an externalTailnets alias; repeating the same arguments is a no-op",
			"external-tailnet add ALIAS --external-id ID [--allow-incoming] " +
				"[--allow-external-references-to SELECTOR ...] [--comment TEXT]",
		},
		{
			commandExternalTailnetRemove,
			"Remove an externalTailnets alias; a referenced alias requires --force",
			"external-tailnet remove ALIAS [--force]",
		},
		{
			commandExternalTailnetList,
			"List externalTailnets aliases",
			"external-tailnet list",
		},
		{cmdMerge, mergeSummary, "merge (--dir DIR [--dir DIR ...] | --base FILE --add FILE) [--out FILE]"},
		{cmdNormalize, "Emit the policy as standard JSON for general-purpose JSON tools", cmdNormalize},
		{cmdValidate, "Validate the policy via the Tailscale API", cmdValidate},
		{
			cmdTest,
			testSummary,
			"test [--watch [--interval DURATION] [--validate]]",
		},
		{
			commandTestAdd,
			"Add deny or accept policy assertions without evaluating them; add never renumbers existing assertion IDs",
			"test add --src SRC (--deny DST:PORT | --accept DST:PORT) [--deny DST:PORT ...] [--accept DST:PORT ...] " +
				"[--src-posture-attr KEY=VALUE ...]",
		},
		{
			commandTestRemove,
			"Remove deny or accept policy assertions; removing may renumber later assertion IDs",
			"test remove --src SRC (--deny DST:PORT | --accept DST:PORT) [--deny DST:PORT ...] [--accept DST:PORT ...] " +
				"[--src-posture-attr KEY=VALUE ...]",
		},
		{
			cmdCheck,
			"Answer one reachability question locally",
			"check --src SRC (--dst DST:PORT | --dst DST --port PORT) [--proto tcp|udp|sctp|any] " +
				"[--posture-attr KEY=VALUE ...] [--posture-attrs-complete]",
		},
		{
			cmdLint,
			lintSummary,
			"lint [-severity advice|info|warn|error] [-wildcard any-to-any|any|off] [-config PATH] " +
				"[-strict-scim-groups] [-scim-domains a.com,b.com] [-online-validation]",
		},
		{cmdJQ, "Query the policy with the embedded jq engine", "jq PROGRAM"},
		{cmdPull, "Bootstrap a local policy from the live tailnet", "pull [--force]"},
		{cmdPlan, "Diff the policy against the live tailnet (read-only)", cmdPlan},
		{cmdUpload, "Upload the policy to the tailnet", "upload [--accept-remote-changes]"},
	}
}

// printSchema emits a machine-readable description of the tool — how to invoke
// it (global flags), what it does (the command catalog), and its exit-code
// contract — so an agent can discover and drive it the way a human reads --help.
func printSchema(w io.Writer, fs *pflag.FlagSet) error {
	var flags []schemaFlag
	fs.VisitAll(func(f *pflag.Flag) {
		flags = append(flags, schemaFlag{Name: f.Name, Usage: f.Usage, Default: f.DefValue})
	})
	doc := struct {
		Name          string                `json:"name"`
		Version       string                `json:"version"`
		SchemaVersion string                `json:"schema_version"`
		Description   string                `json:"description"`
		Sanitization  string                `json:"sanitization"`
		Flags         []schemaFlag          `json:"flags"`
		Commands      []schemaCommand       `json:"commands"`
		Capabilities  schemaCapabilities    `json:"capabilities"`
		LintFindings  []aclpolicy.LintCheck `json:"lint_findings"`
		ExitCodes     map[string]string     `json:"exit_codes"`
	}{
		Name:          toolName,
		Version:       version,
		SchemaVersion: schemaVersion,
		Description:   "Make typed edits to a Tailscale policy file and query, pull, merge, normalize, validate, test, check, lint, plan, or upload it.",
		Sanitization: "TAILSCALE_SANITIZE=off|identity|strict sanitizes rendered output after evaluation; " +
			"a non-off environment value overrides --sanitize. normalize, plan, and jq refuse active " +
			"sanitization because policy bytes and policy diffs cannot be mechanically sanitized safely. " +
			"Set TAILSCALE_SANITIZE_KEY (64 hex characters) for operator-scoped placeholders that remain comparable across runs; " +
			"without it placeholders are artifact-scoped.",
		Flags:    flags,
		Commands: commandCatalog(),
		Capabilities: schemaCapabilities{
			TypedEdits: schemaTypedEditCapability{
				Formats:           []string{formatJSON, policyFormatHuJSON},
				PreservesComments: true,
				AuthorsComments:   true,
			},
		},
		LintFindings: aclpolicy.LintCatalog(),
		ExitCodes: map[string]string{
			"0": "success or reachable; server validation warnings with no errors and no message are " +
				"non-fatal; test also uses 0 for indeterminate assertions under --indeterminate=ignore",
			"1": "operation or policy assertion failed, not reachable, or test had an unsettleable assertion under --indeterminate=fail",
			"2": "usage, input, or collection error; for pull, validate, and plan this also covers a control plane " +
				"that never judged the policy (expired credentials, rate limiting, a server fault, an " +
				"unreadable body, a redirect that dropped the request, or an unreachable API), and no " +
				"verdict is printed in that case. For test --watch, also signals an unreadable --file, " +
				"a non-positive --interval, incompatible flag combinations (--indeterminate with --watch, " +
				"--interval without --watch, --validate without --watch), or a failed write to stdout. " +
				"For test --watch --validate it additionally covers a missing --tailnet or API/OAuth credentials, " +
				"which is checked before the loop starts, and a control plane that never judged a " +
				"snapshot (authentication, authorization, rate_limited, transport, or response), which " +
				"is reported as one last composite record before the watcher stops. An interrupt during " +
				"a non-watch command that is mid-request exits here too rather than as a verdict; for " +
				"upload that means the change may already have been applied. Interrupting either watch " +
				"mode still exits 0, in-flight validation included",
			"10": "indeterminate: check could not settle the question, test had an unsettleable assertion under " +
				"--indeterminate=warn, or validate and plan got a response they cannot read as a verdict " +
				"(warnings with no errors alongside a message, or a detail with neither errors nor warnings)",
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// commandHelp renders one command's own help, which is what every command
// except root now answers --help with. cobra's default help is the command's
// Long (or Short) followed by its usage template, and that template is the only
// rendering that splits a command's local flags from the inherited ones — the
// distinction the whole-tool page cannot make. Its default help function is
// unreachable once SetHelpFunc overrides it (Command.helpFunc is unexported and
// HelpFunc walks up to the override), so those two pieces are reproduced here.
//
// UsageString is avoided deliberately: its non-nil-error path funnels through
// cobra.CheckErr, which calls [os.Exit]. cmd.Usage() renders the same template
// and returns the error instead.
func commandHelp(cmd *cobra.Command) {
	out := cmd.OutOrStdout()
	// Usage writes to OutOrStderr, and the two resolve to the same writer only
	// once a caller has wired one; pin it so help lands on stdout either way.
	cmd.SetOut(out)
	if text := cmp.Or(cmd.Long, cmd.Short); text != "" {
		fmt.Fprintf(out, "%s\n\n", strings.TrimRight(text, " \t\n"))
	}
	if err := cmd.Usage(); err != nil {
		cmd.PrintErrln(err)
	}
	// The exit-code scheme is a property of the tool, not of one command, and
	// AX convention 7 requires --help to carry it; point at the page that does
	// rather than repeating four exit codes under every command.
	fmt.Fprintf(out, "\nRun \"%s --help\" for the exit-code scheme and the full command list.\n", cmd.Root().Name())
}

func usage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintln(w, "tsacl: pull, edit, query, merge, normalize, validate, test, check, lint, plan, and upload"+
		" a Tailscale ACL policy.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The result is written to stdout (human text, or a versioned JSON envelope")
	fmt.Fprintln(w, "with -format json); logs and errors go to stderr.")
	fmt.Fprintf(w, "\nUsage:\n  %s [global flags] COMMAND [command flags]\n", filepath.Base(os.Args[0]))
	fmt.Fprintln(w, "\nCommands:")
	// The name column follows the longest catalog entry rather than a literal
	// width, so a command longer than the one that set it — "auto-approver
	// remove" against a hardcoded 14 — cannot silently break the alignment.
	catalog := commandCatalog()
	nameWidth := 0
	for _, c := range catalog {
		nameWidth = max(nameWidth, len(c.Name))
	}
	for _, c := range catalog {
		fmt.Fprintf(w, "  %-*s %s\n", nameWidth, c.Name, c.Summary)
	}
	fmt.Fprintln(w, "\nGlobal flags:")
	// PrintDefaults writes to the FlagSet's own configured output (stderr by
	// default), not to w, so point it at w explicitly before calling it.
	fs.SetOutput(w)
	fs.PrintDefaults()
	fmt.Fprint(w, usageRosterNote)
	fmt.Fprint(w, usageAuthenticationNote)
	fmt.Fprint(w, usageSanitizationNote)
	fmt.Fprint(w, usageUploadNote)
	fmt.Fprint(w, usageAgentNote)
	fmt.Fprint(w, usageExamples)
	fmt.Fprint(w, usageExitCodes)
}

// usageExamples is one block rather than a run of Fprintln calls, for the same
// reason as usageExitCodes below. It also keeps usage() off the funlen limit:
// every new command adds an example, and a run of Fprintln calls made that a
// statement each, so two branches adding a command apiece broke the build on
// merge without either one exceeding the limit alone.
const usageExamples = `
Examples:
  tsacl --file acl.json init
  tsacl --file acl.json grant add --src autogroup:member --dst tag:web --ip tcp:443
  tsacl --file acl.json group add --name group:eng --member alice@example.com --member bob@example.com
  tsacl --file acl.json ipset add --name ipset:office --cidr 10.0.0.0/8
  tsacl --file acl.json ipset add --name ipset:trimmed --member 'add ipset:office' --member 'remove 10.1.0.0/16'
  tsacl --file acl.json ssh add --action check --src autogroup:member --dst tag:server --user root --check-period 12h
  tsacl --file acl.hujson tag-owner add tag:web autogroup:admin  # comments preserved
  tsacl --file acl.json posture set posture:labCompliant "custom:labCompliant == true"
  tsacl --file acl.hujson auto-approver add --route 10.0.0.0/8 --approver group:neteng --comment "Lab subnet routers"
  tsacl --file acl.hujson auto-approver add --exit-node --approver tag:exit-node
  tsacl --file acl.hujson external-tailnet add partner --external-id tn-123 --allow-incoming
  tsacl --file acl.hujson auto-approver remove --route 10.0.0.0/8 --approver group:neteng
  tsacl --file acl.json host set web 100.64.0.10 --comment "Legacy monitoring endpoint"
  tsacl --file acl.json grant add --src autogroup:member --dst tag:web --ip tcp:443 --src-posture posture:labCompliant
  tsacl --file acl/acl.generated.json merge --dir initial-30 --dir peer-relay-internal
  tsacl --file acl/acl.generated.json normalize | jq -r 'paths | join(".")'
  tsacl --file acl/acl.generated.json pull        # bootstrap once from the live tailnet
  tsacl --file acl/acl.generated.json test        # run native policy assertions locally
  tsacl --file acl.json test add --src alice@example.com --deny tag:db:5432
  tsacl --file acl.json test add --src alice@example.com --accept tag:web:443
  tsacl --file acl.json test remove --src alice@example.com --deny tag:db:5432
  tsacl --indeterminate=fail --file acl/acl.generated.json test # fail CI on an unsettled assertion
  tsacl --file acl/acl.generated.json test --watch  # re-run on every save
  tsacl -format json --file acl/acl.generated.json test --watch # NDJSON, one verdict per line
  tsacl --file acl.hujson test --watch --validate # local plus read-only server verdict
  tsacl --file acl/acl.generated.json check --src alice@example.com --dst tag:web:443
  tsacl --file acl/acl.generated.json check --src tag:app --dst tag:db --port 5432
  tsacl --file acl/acl.generated.json check --src tag:app --dst tag:dns:53 --proto udp
  tsacl --file acl/acl.generated.json check --src tag:app --dst tag:sig:5060 --proto sctp
  tsacl --file acl/acl.generated.json lint         # static policy hygiene findings
  tsacl --file acl.hujson jq '.grants[] | .src'    # NDJSON query results
  tsacl --file acl/acl.generated.json lint -config acl/lint.hujson
  tsacl -strict --file acl/acl.generated.json test # fail if any rule is unparseable
  tsacl --file acl/acl.generated.json plan        # diff against the live tailnet
  tsacl --file acl/acl.generated.json upload      # use plan's recorded ETag
  tsacl --file acl/acl.generated.json upload --accept-remote-changes # explicit no-If-Match opt-out
  tsacl -schema                                   # machine-readable schema
`

// usageRosterNote elaborates --roster beyond its one-line flag summary: the
// difference between "unknown" and "does not hold that role" is exactly what
// supplying the file asserts, which a single usage line cannot carry.
const usageRosterNote = `
  --roster PATH   test/check only. A JSON roster mapping login to tailnet role,
                  either {"login": "role"} or the users endpoint's
                  {"users":[{"loginName":...,"role":...}]}. Supplying it asserts
                  the roster is COMPLETE and AUTHORITATIVE: a login it does not
                  list is treated as definitely not holding any role. Without
                  it, role autogroups cannot be resolved and exit 10 is
                  returned.
`

const usageUploadNote = `
  upload safety   plan and pull record the observed ETag in
                  .tsacl-state.json beside --file, keyed by tailnet (add it to
                  the policy repo's .gitignore: it names the tailnet). Upload
                  uses that ETag by default and refuses if the record is absent,
                  unreadable, or stale. --if-match explicitly overrides the
                  record. --accept-remote-changes is the explicit opt-out that
                  sends no If-Match; it cannot be combined with --if-match.
`

const usageAuthenticationNote = `
  OAuth credentials   --oauth-client-id/--oauth-client-secret (or
                      TAILSCALE_OAUTH_CLIENT_ID/TAILSCALE_OAUTH_CLIENT_SECRET)
                      use the client-credentials grant. validate, pull, plan,
                      and test --watch --validate request the policy_file:read
                      scope; upload requests policy_file. An explicitly
                      supplied credential wins over an environment variable of
                      the other class; supplying both explicitly is an error,
                      as is a client ID without its secret. The client secret
                      is never reported. lint --online-validation also reads
                      vip-services, which no OAuth scope covers, so its
                      svc-unknown findings are skipped for an OAuth client and
                      need --api-key to run.
`

const usageSanitizationNote = `
  output sanitization   TAILSCALE_SANITIZE accepts off, identity, or strict and
                        overrides --sanitize whenever the environment value is
                        non-off. Active sanitization is announced on stderr and
                        applied only after evaluation. normalize, plan, and jq
                        refuse active sanitization because policy bytes and
                        policy diffs cannot be mechanically sanitized safely.
                        Error text and log lines on stderr are scrubbed too,
                        including any email-shaped token.
                        TAILSCALE_SANITIZE_KEY accepts exactly 64 hexadecimal
                        characters for stable, operator-scoped placeholders;
                        without it placeholders are artifact-scoped.
`

// usageExitCodes is one block rather than a run of Fprintln calls so the help
// text reads as the paragraph it is. Keep it ASCII: stdout stays parse-clean
// across a Windows pipe boundary.
const usageAgentNote = `
Agents and automation:
  AGENT_MODE=1 selects JSON output when -format is not given; a pipe alone does
  not. Every failure writes one JSON error line to stderr (error_code, message,
  retryable, trace_id) and exits with the code below. -dry-run previews any
  write and leaves the policy and state files untouched. -format json upload
  needs -yes. tsacl __schema [--as=mcp] describes the tool, and tsacl mcp-server
  serves it over MCP; give it credentials through the environment, not flags.
`

const usageExitCodes = `
Exit codes:
  0  success; check reports reachable. Server validation that returns warnings
     with no errors and no message is a success - the warnings are logged and
     reported, not fatal.
  1  operation or policy assertion failed; check reports not reachable
  2  usage, input, or collection error. For pull, validate, plan, and lint
     --online-validation this also covers a control plane that never judged the
     policy (expired credentials, rate limiting, a server fault, an unreadable
     response body, a redirect that dropped the request, or an unreachable API).
     No verdict is printed for a request that reached no answer, except under
     lint --online-validation, which still reports the offline findings it had
     already computed.
  10 indeterminate: a rule would have applied but depends on a fact absent from
     the policy file (device posture, via routing, or a role autogroup such as
     autogroup:admin), or a rule overlapping the query could not be parsed.
     Not a denial - verify it another way. Also returned by test when an
     assertion could not be settled (its --indeterminate default is warn; fail
     maps it to 1, ignore maps it to 0 without hiding the finding), and by
     validate and plan for a response that cannot be read as a verdict:
     warnings with no errors but also a message, or a detail entry carrying
     neither errors nor warnings.

Test precondition:
  Server-side validate is the only check that catches an unreadable port or
  protocol, which is what produces exit 10. lint catches dangling group, host,
  tag, and ipset references, which local evaluation silently treats as matching
  nothing; --indeterminate does not weaken check's verdict.

Watch mode:
  test --watch never exits non-zero for a test verdict: an exit code is a
  point-in-time verdict and a watch loop has no single point in time. It exits 0
  on interrupt whatever the last run said, so use plain test in CI. Exit 2 still
  signals the watcher's own failures - an unreadable --file, a non-positive
  --interval, --indeterminate and --interval where they cannot apply, or a write
  that fails and returns an error, such as a full disk. Piping into a reader
  that exits early, e.g. test --watch | head -1, does not return you to a
  prompt. A broken pipe is only detected by writing, and nothing is written
  between saves, so the watcher keeps polling until the policy file next
  changes. That write then fails, and the outcome is platform-specific: on Unix
  the Go runtime raises SIGPIPE (signal 13) on the failed write to fd 1, and the
  default disposition kills the process with exit 141 before this tool's own
  error handling runs. On Windows, where there is no SIGPIPE, the failed write
  is reported as an ordinary error, so this exits 2 through the same path as a
  full disk. Interrupt the watcher to stop it; do not expect the pipe to.

Authoritative watch (--validate):
  test --watch --validate explicitly enables credentialed, read-only network
  access and emits one composite local/server record per stable snapshot;
  credentials alone never enable networking, so plain test --watch stays
  offline whatever the environment holds. It requires --tailnet and API/OAuth
  credentials, both checked before the loop starts. Policy verdicts remain stream data, but
  a control plane that never judged a snapshot ends the watcher with exit 2
  after emitting its sanitized evidence.

Interrupts:
  The first interrupt cancels the run: either watch mode stops and exits 0,
  in-flight validation included, while a non-watch command that is mid-request
  abandons it and exits 2, not 1 - an interrupt is not a verdict, and for
  upload the change may already have been applied
  server-side. A second interrupt is handled by the runtime's default
  disposition, so a command wedged in a syscall that cannot observe the
  cancellation still dies on Ctrl-C twice.
`

type stringListFlag []string

func (f *stringListFlag) Set(value string) error {
	if value == "" {
		return errors.New("value cannot be empty")
	}
	*f = append(*f, value)
	return nil
}

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

// Type satisfies pflag.Value. The name appears in --help as the flag's
// argument placeholder.
func (f *stringListFlag) Type() string { return "stringList" }
