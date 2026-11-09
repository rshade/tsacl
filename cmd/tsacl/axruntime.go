package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/rshade/ax-go"
	"github.com/spf13/cobra"

	"github.com/rshade/tsacl/internal/tailapi"
)

const (
	errCodeValidation    = "validation_error"
	errCodeIndeterminate = "indeterminate"
	errCodeInterrupted   = "interrupted"
	errCodeRateLimited   = "rate_limited"
	errCodeUnavailable   = "control_plane_unavailable"
	errCodeFailed        = "command_failed"

	httpTooManyRequests = 429
)

// exitStatusError carries an exit code decided by the ax-go runtime for a
// failure that never reached a tsacl command, so run still reports it.
type exitStatusError struct{ code int }

func (e exitStatusError) Error() string { return "exit status " + strconv.Itoa(e.code) }

// axErrorFor translates a command error into the ax-go error envelope. The
// exit code always comes from exitCode, which stays the single source of the
// 0/1/2/10 scheme.
func axErrorFor(ctx context.Context, err error, extra ...ax.ErrorOption) *ax.Error {
	if existing, ok := errors.AsType[*ax.Error](err); ok {
		return existing
	}
	code := errCodeFailed
	opts := append([]ax.ErrorOption{ax.WithErrorTool(toolName), ax.WithErrorExitCode(exitCode(err))}, extra...)

	var usage usageError
	unavailable, isUnavailable := errors.AsType[*tailapi.ValidationUnavailableError](err)
	switch {
	case errors.Is(err, errReachabilityIndeterminate),
		tailapi.ClassifyValidation(err) == tailapi.ValidationIndeterminate:
		code = errCodeIndeterminate
	case errors.As(err, &usage):
		code = errCodeValidation
	case errors.Is(err, context.Canceled):
		code = errCodeInterrupted
	case isUnavailable:
		code = errCodeUnavailable
		if unavailable.Status == httpTooManyRequests {
			code = errCodeRateLimited
			opts = append(opts, ax.WithRetryable(true))
			if seconds, ok := retryAfterSeconds(unavailable.RetryAfter); ok {
				opts = append(opts, ax.WithRetryAfterSeconds(seconds))
			}
		}
	}
	return ax.NewError(ctx, code, err.Error(), opts...)
}

// runtimeOptions configures ax.Execute. WithStdoutIsTTY(true) is deliberate:
// ax-go would otherwise resolve a non-terminal stdout to JSON, and a piped
// human caller such as "tsacl normalize | jq" must keep receiving bare bytes.
func runtimeOptions(getenv func(string) string, stdout, stderr io.Writer, logger ax.Logger) []ax.ExecuteOption {
	return []ax.ExecuteOption{
		ax.WithStdout(stdout),
		ax.WithStderr(stderr),
		ax.WithEnv(getenv),
		ax.WithStdoutIsTTY(true),
		ax.WithVersion(ax.ResolveVersion(version)),
		ax.WithFlushFunc(func(ctx context.Context) error { return ax.Flush(ctx, logger) }),
	}
}

// withExitStatus keeps a failure the runtime reported before any tsacl command
// ran visible to callers that classify errors with exitCode.
func withExitStatus(commandErr error, code int) error {
	if commandErr == nil && code != exitOK {
		return exitStatusError{code: code}
	}
	return commandErr
}

func retryAfterSeconds(header string) (int64, bool) {
	seconds, err := strconv.ParseInt(strings.TrimSpace(header), 10, 64)
	return seconds, err == nil && seconds > 0
}

// classifyCobraError marks the plain-text "unknown command" errors cobra
// raises as usage errors; everything else passes through.
func classifyCobraError(err error) error {
	if err != nil && strings.HasPrefix(err.Error(), "unknown command") {
		return usageError{err}
	}
	return err
}

// rootForArgs returns the command ax.Execute should run. Cobra's traversal of
// ancestor flags fails before any hook or RunE can see it, so a failing
// traversal is reported through a stub root and keeps the full ax-go lifecycle.
func rootForArgs(root *cobra.Command, args []string, finish func(*cobra.Command, error) error) *cobra.Command {
	root.SetArgs(args)
	_, _, traverseErr := root.Traverse(args)
	if traverseErr == nil {
		return root
	}
	stub := &cobra.Command{Use: toolName}
	stub.SetArgs([]string{})
	stub.RunE = func(cmd *cobra.Command, _ []string) error {
		return finish(cmd, usageError{traverseErr})
	}
	return stub
}

// adaptTree routes every error cobra can raise for a command through finish:
// RunE, the persistent pre-run hook, and positional-argument validation. Flag
// parse errors take the same route through the root's FlagErrorFunc.
func adaptTree(root *cobra.Command, finish func(*cobra.Command, error) error) {
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		if inner := cmd.RunE; inner != nil {
			cmd.RunE = func(c *cobra.Command, args []string) error { return finish(c, inner(c, args)) }
		}
		if inner := cmd.PersistentPreRunE; inner != nil {
			cmd.PersistentPreRunE = func(c *cobra.Command, args []string) error {
				if err := inner(c, args); err != nil {
					return finish(c, err)
				}
				return nil
			}
		}
		if inner := cmd.Args; inner != nil {
			cmd.Args = func(c *cobra.Command, args []string) error {
				if err := inner(c, args); err != nil {
					return finish(c, err)
				}
				return nil
			}
		}
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(root)
}

// resolveFormat turns an unset --format into the mode ax-go resolved:
// flag, then AGENT_MODE, then human (stdout is declared a terminal, so a pipe
// alone never selects JSON).
func resolveFormat(ctx context.Context, format string) string {
	if format != "" {
		return format
	}
	if mode, ok := ax.ModeFromContext(ctx); ok && mode == ax.ModeJSON {
		return formatJSON
	}
	return formatHuman
}

// metaFor returns the correlation metadata for a JSON-mode call, or nil.
func metaFor(ctx context.Context, format string) *ax.Metadata {
	if format != formatJSON {
		return nil
	}
	meta := ax.MetadataFromContext(ctx)
	return &meta
}

func withMeta(ctx context.Context, format string, res *result) *result {
	if res != nil {
		res.Meta = metaFor(ctx, format)
	}
	return res
}

// declareNonDeterministic registers every runnable command as emitting the
// result envelope so __schema lists meta.trace_id, meta.span_id and
// meta.idempotency_key as the fields that differ between runs.
func declareNonDeterministic(root *cobra.Command) {
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		if cmd.Runnable() && cmd != root {
			ax.WithNonDeterministicFields[result](cmd)
		}
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(root)
}

// verdictContext carries a verdict's result envelope on the ax.Error. The MCP
// server returns only the error for a non-zero exit, so a check that is "not
// reachable" (1) or indeterminate (10), a failed test, or a lint finding would
// otherwise lose its evidence. The policy text and diff are left out; they are
// bulky and the caller already holds the file.
func verdictContext(underMCP *atomic.Bool, res *result) []ax.ErrorOption {
	if !underMCP.Load() || res == nil {
		return nil
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return nil
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		return nil
	}
	for _, key := range []string{"policy", "diff", "meta"} {
		delete(fields, key)
	}
	return []ax.ErrorOption{ax.WithErrorContext(fields)}
}
