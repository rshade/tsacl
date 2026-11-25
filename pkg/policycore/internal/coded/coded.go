// Package coded builds the ax-go contract errors policycore returns for bad
// input, so every one carries the same retryability, exit code, and empty
// runtime metadata by construction.
//
// A failure is classified once, where it is detected, with New or Errorf.
// Callers inside policycore keep wrapping it with [fmt.Errorf] as before,
// and every exported function returns through Boundary, which lifts the
// innermost classification to the top of the chain with the full message.
package coded

import (
	"context"
	"errors"
	"fmt"

	"github.com/rshade/ax-go/contract"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
)

// New classifies err with code. The message is err's text, unchanged, and err
// stays reachable through Unwrap. It panics on a code outside errcode.All,
// which is a programming error that tests catch.
func New(code string, err error) *contract.Error {
	fix := errcode.Fix(code)
	if fix == "" {
		panic(fmt.Sprintf("coded: %q is not in the errcode vocabulary", code))
	}
	return build(code, fix, err)
}

// Errorf is New with a cause formatted by [fmt.Errorf].
func Errorf(code, format string, args ...any) *contract.Error {
	return New(code, fmt.Errorf(format, args...))
}

// Boundary prepares err for return from an exported function. It returns an
// untyped nil for nil, err itself when err is already a *contract.Error, and
// err unchanged when its chain holds no *contract.Error (an I/O or programmer
// error). Otherwise it returns a new *contract.Error carrying the first
// classified error's code and fix, err's full text as the message, and err as
// the cause, so [errors.As] finds a message equal to err.Error().
func Boundary(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(*contract.Error); ok { //nolint:errorlint // only a top-level envelope already carries the full message
		return err
	}
	inner, ok := errors.AsType[*contract.Error](err)
	if !ok {
		return err
	}
	return build(inner.ErrorCode, inner.ActionableFix, err)
}

func build(code, fix string, err error) *contract.Error {
	built := contract.NewError(context.Background(), code, err.Error(),
		contract.WithActionableFix(fix),
		contract.WithRetryable(false),
		contract.WithErrorExitCode(contract.ExitValidation),
		contract.WithErrorCause(err),
	)
	// ax.Execute stamps the live trace ID, tool, and version only into empty
	// fields; NewError would otherwise leave an all-zero trace ID behind.
	built.TraceID, built.Tool, built.Version = "", "", ""
	return built
}
