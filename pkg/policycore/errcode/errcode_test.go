package errcode_test

import (
	"slices"
	"testing"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
)

func TestVocabularyIsSortedUniqueAndFixed(t *testing.T) {
	t.Parallel()

	codes := errcode.All()
	if !slices.IsSorted(codes) {
		t.Errorf("All() is not sorted: %v", codes)
	}
	seenFix := map[string]string{}
	for index, code := range codes {
		if index > 0 && codes[index-1] == code {
			t.Errorf("All() lists %q twice", code)
		}
		fix := errcode.Fix(code)
		if fix == "" {
			t.Errorf("Fix(%q) is empty", code)
			continue
		}
		if other, ok := seenFix[fix]; ok {
			t.Errorf("Fix(%q) repeats the fix for %q: %q", code, other, fix)
		}
		seenFix[fix] = code
	}
	if got := errcode.Fix("not_a_code"); got != "" {
		t.Errorf("Fix(unknown) = %q, want empty", got)
	}
}
