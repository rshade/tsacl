package coded_test

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/rshade/ax-go/contract"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/internal/coded"
	"github.com/rshade/tsacl/pkg/policycore/internal/codedtest"
)

type detailError struct{ detail string }

func (e *detailError) Error() string { return e.detail }

func TestBoundaryOfNilIsUntypedNil(t *testing.T) {
	t.Parallel()

	if err := coded.Boundary(nil); err != nil {
		t.Fatalf("Boundary(nil) = %#v, want an untyped nil", err)
	}
}

func TestBoundaryLiftsTheInnermostCodeWithTheFullMessage(t *testing.T) {
	t.Parallel()

	detail := &detailError{detail: "needs an explicit operation"}
	inner := coded.New(errcode.IPSetOperationAmbiguous, detail)
	wrapped := fmt.Errorf("ipset:x member 2: %w", fmt.Errorf("ipset:y: %w", inner))

	err := coded.Boundary(wrapped)

	codedtest.Assert(t, err, errcode.IPSetOperationAmbiguous,
		"ipset:x member 2: ipset:y: needs an explicit operation")
	if got, found := errors.AsType[*detailError](err); !found || got != detail {
		t.Errorf("errors.As lost the original typed cause: %v, %v", got, found)
	}
}

func TestBoundaryKeepsATopLevelEnvelope(t *testing.T) {
	t.Parallel()

	top := coded.Errorf(errcode.IPSetUndefined, "%s is not a defined ipset", "ipset:x")
	if err := coded.Boundary(top); err != top { //nolint:errorlint // identity is the property under test
		t.Errorf("Boundary rebuilt a top-level envelope: %v", err)
	}
	codedtest.Assert(t, top, errcode.IPSetUndefined, "ipset:x is not a defined ipset")
}

func TestBoundaryLeavesUnclassifiedErrorsAlone(t *testing.T) {
	t.Parallel()

	missing := fmt.Errorf("open x: %w", fs.ErrNotExist)
	err := coded.Boundary(missing)
	if err != missing { //nolint:errorlint // identity is the property under test
		t.Errorf("Boundary(%v) = %v, want it unchanged", missing, err)
	}
	if _, ok := errors.AsType[*contract.Error](err); ok {
		t.Error("an unclassified error became a *contract.Error")
	}
}

func TestNewPanicsOnAnUnknownCode(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("New accepted a code outside the vocabulary")
		}
	}()
	_ = coded.New("not_a_code", errors.New("x"))
}
