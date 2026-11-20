package aclpolicy_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rshade/ax-go/contract"

	"github.com/rshade/tsacl/internal/aclpolicy"
	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/hujsonedit"
)

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func errorCode(t *testing.T, err error) string {
	t.Helper()
	envelope, ok := errors.AsType[*contract.Error](err)
	if !ok {
		t.Fatalf("%v (%T) does not unwrap to *contract.Error", err, err)
	}
	return envelope.ErrorCode
}

func TestFilesClassifyAMalformedPolicy(t *testing.T) {
	t.Parallel()
	path := writePolicy(t, `{"grants": [,}`)
	_, err := aclpolicy.Files{}.Load(path)
	if code := errorCode(t, err); code != errcode.ConfigInvalid {
		t.Errorf("error_code = %q, want %q", code, errcode.ConfigInvalid)
	}
	want := path + ": hujson: line 1, column 13: invalid character ',' at start of value"
	if err.Error() != want {
		t.Errorf("Error() = %q, want the unchanged %q", err.Error(), want)
	}
}

func TestFilesApplyTheirLimitToEveryEntryPoint(t *testing.T) {
	t.Parallel()
	const policy = `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`
	path := writePolicy(t, policy)
	files := aclpolicy.Files{Limits: hujsonedit.Options{MaxBytes: int64(len(policy)) - 1}}

	_, loadErr := files.Load(path)
	_, rawErr := files.ReadRaw(path)
	_, normalizeErr := files.Normalize(path)
	_, commentsErr := files.LeadingComments(path, "grants")
	_, mergeErr := files.MergePair(path, path)
	patchErr := files.WritePatch(path, aclpolicy.PatchAdd([]string{}, "groups"))
	_, lintErr := files.LoadLintConfig(path)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "acl.hujson"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, dirsErr := files.MergeDirectories([]string{dir}, filepath.Join(t.TempDir(), "out.json"))
	for name, err := range map[string]error{
		"Load": loadErr, "ReadRaw": rawErr, "Normalize": normalizeErr,
		"LeadingComments": commentsErr, "MergePair": mergeErr, "WritePatch": patchErr,
		"LoadLintConfig": lintErr, "MergeDirectories": dirsErr,
	} {
		if code := errorCode(t, err); code != errcode.ConfigTooLarge {
			t.Errorf("%s error_code = %q, want %q", name, code, errcode.ConfigTooLarge)
		}
	}
	if _, err := (aclpolicy.Files{Limits: hujsonedit.Options{MaxBytes: int64(len(policy))}}).Load(path); err != nil {
		t.Errorf("Load at exactly the limit = %v, want success", err)
	}
}
