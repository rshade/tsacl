// Package codedtest asserts the error contract policycore tests share: one
// classified code, the vocabulary's fix, an unchanged message, retryable
// false, exit code 2, and empty runtime metadata.
package codedtest

import (
	"errors"
	"slices"
	"testing"

	"github.com/rshade/ax-go/contract"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
)

// Case is one failing input, the code it must carry, and the text it produced
// before errors were typed.
type Case struct {
	Name string
	Code string
	Text string
	Err  error
}

// Run asserts the contract on every case as a parallel subtest.
func Run(t *testing.T, cases []Case) {
	t.Helper()
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			Assert(t, test.Err, test.Code, test.Text)
		})
	}
}

// Assert checks that err carries code and text under the policycore contract.
func Assert(t *testing.T, err error, code, text string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want %s %q", code, text)
	}
	if got := err.Error(); got != text {
		t.Errorf("Error() = %q, want the unchanged %q", got, text)
	}
	envelope, ok := errors.AsType[*contract.Error](err)
	if !ok {
		t.Fatalf("%T does not unwrap to *contract.Error", err)
	}
	if !slices.Contains(errcode.All(), envelope.ErrorCode) {
		t.Errorf("ErrorCode %q is not in errcode.All()", envelope.ErrorCode)
	}
	if envelope.ErrorCode != code {
		t.Errorf("ErrorCode = %q, want %q", envelope.ErrorCode, code)
	}
	if envelope.Message != err.Error() {
		t.Errorf("Message = %q, want Error() %q", envelope.Message, err.Error())
	}
	if envelope.ActionableFix != errcode.Fix(code) {
		t.Errorf("ActionableFix = %q, want %q", envelope.ActionableFix, errcode.Fix(code))
	}
	if envelope.Retryable == nil || *envelope.Retryable {
		t.Errorf("Retryable = %v, want an explicit false", envelope.Retryable)
	}
	if got := envelope.ExitCode(); got != contract.ExitValidation {
		t.Errorf("ExitCode() = %d, want %d", got, contract.ExitValidation)
	}
	if envelope.TraceID != "" || envelope.Tool != "" || envelope.Version != "" {
		t.Errorf("runtime metadata = %q/%q/%q, want all empty", envelope.TraceID, envelope.Tool, envelope.Version)
	}
	if len(envelope.Context) != 0 || len(envelope.Suggestions) != 0 {
		t.Errorf("Context = %v, Suggestions = %v, want both empty", envelope.Context, envelope.Suggestions)
	}
}
