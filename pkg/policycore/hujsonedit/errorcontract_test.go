package hujsonedit_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rshade/ax-go/config"
	"github.com/rshade/ax-go/contract"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/hujsonedit"
	"github.com/rshade/tsacl/pkg/policycore/internal/codedtest"
)

const malformed = `{"grants": [,}` + "\n"

const malformedDetail = "hujson: line 1, column 13: invalid character ',' at start of value"

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// paddedDocument is a valid HuJSON object of exactly size bytes.
func paddedDocument(size int64) string {
	const prefix, suffix = `{"pad": "`, `"}`
	return prefix + strings.Repeat("a", int(size)-len(prefix)-len(suffix)) + suffix
}

func parseErr(path string) error {
	_, err := hujsonedit.ParseFile(path)
	return err
}

func heldParseErr(name, document string) error {
	_, err := hujsonedit.Parse(name, []byte(document))
	return err
}

func leadingErr(path string, segments ...string) error {
	_, err := hujsonedit.LeadingComments(path, nil, segments...)
	return err
}

func patchErr(document string, operations ...hujsonedit.PatchOperation) error {
	_, err := hujsonedit.PatchBytes([]byte(document), nil, operations...)
	return err
}

// The Text fields were captured from main before errors were typed; each must
// stay byte-identical.
func TestHuJSONErrorContract(t *testing.T) {
	t.Parallel()

	bad := writeFile(t, "bad.hujson", malformed)
	// Every edit below fails, so the shared file is never rewritten.
	goodPath := writeFile(t, "good.hujson", `{"groups": {"group:a": ["x"]}, "list": [1], "lit": 3}`+"\n")
	const newline = "comment text must be one line: it must not contain a carriage return or newline"
	codedtest.Run(t, []codedtest.Case{
		{Name: "ParseFile malformed", Code: errcode.ConfigInvalid, Err: parseErr(bad),
			Text: bad + ": " + malformedDetail},
		{Name: "Parse held bytes", Code: errcode.ConfigInvalid, Err: heldParseErr("policy.hujson", malformed),
			Text: "policy.hujson: " + malformedDetail},
		{Name: "WritePatch malformed", Code: errcode.ConfigInvalid,
			Err: hujsonedit.WritePatch(bad, nil, hujsonedit.PatchAdd(1, "x")), Text: bad + ": " + malformedDetail},
		{Name: "WritePatch remove absent", Code: errcode.ConfigPatchInvalid,
			Err:  hujsonedit.WritePatch(goodPath, nil, hujsonedit.PatchRemove("groups", "group:absent")),
			Text: goodPath + ": applying patch: hujson: patch operation 0: value not found"},
		{Name: "WritePatch comment newline", Code: errcode.CommentInvalid,
			Err:  hujsonedit.WritePatch(goodPath, nil, hujsonedit.PatchComment("a\nb", "groups", "group:a")),
			Text: goodPath + ": commenting: " + newline},
		{Name: "WritePatch comment on absent node", Code: errcode.ConfigPatchInvalid,
			Err:  hujsonedit.WritePatch(goodPath, nil, hujsonedit.PatchComment("hi", "groups", "group:absent")),
			Text: goodPath + ": commenting: no node at /groups/group:absent"},
		{Name: "WritePatch comment into literal", Code: errcode.ConfigPatchInvalid,
			Err:  hujsonedit.WritePatch(goodPath, nil, hujsonedit.PatchComment("hi", "lit", "x")),
			Text: goodPath + ": commenting: cannot index into a literal at /lit/x"},
		{Name: "PatchBytes malformed", Code: errcode.ConfigInvalid,
			Err: patchErr(malformed, hujsonedit.PatchAdd(1, "x")), Text: malformedDetail},
		{Name: "PatchBytes remove absent", Code: errcode.ConfigPatchInvalid,
			Err:  patchErr(`{"groups": {}}`, hujsonedit.PatchRemove("groups", "group:absent")),
			Text: "applying patch: hujson: patch operation 0: value not found"},
		{Name: "LeadingComments malformed", Code: errcode.ConfigInvalid, Err: leadingErr(bad, "grants"),
			Text: bad + ": " + malformedDetail},
		{Name: "LeadingComments into literal", Code: errcode.ConfigPatchInvalid, Err: leadingErr(goodPath, "lit", "x"),
			Text: goodPath + ": cannot index into a literal at /lit/x"},
		{Name: "LeadingComments bad array index", Code: errcode.ConfigPatchInvalid,
			Err:  leadingErr(goodPath, "list", "nope"),
			Text: goodPath + `: /list/nope: array index must be a number or "-", got "nope"`},
		{Name: "comment text empty", Code: errcode.CommentInvalid, Err: hujsonedit.ValidateCommentText(" "),
			Text: "comment text must not be empty"},
		{Name: "comment text carriage return", Code: errcode.CommentInvalid,
			Err: hujsonedit.ValidateCommentText("a\rb"), Text: newline},
		{Name: "comment text invalid UTF-8", Code: errcode.CommentInvalid,
			Err: hujsonedit.ValidateCommentText("\xff"), Text: "comment text must be valid UTF-8"},
	})
}

func TestMissingFileStaysUntyped(t *testing.T) {
	t.Parallel()

	err := parseErr(filepath.Join(t.TempDir(), "missing.hujson"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ParseFile(missing) = %v, want fs.ErrNotExist", err)
	}
	if _, ok := errors.AsType[*contract.Error](err); ok {
		t.Error("a missing file became a *contract.Error")
	}
}

func TestUnencodableValueStaysUntyped(t *testing.T) {
	t.Parallel()

	err := patchErr(`{}`, hujsonedit.PatchAdd(make(chan int), "x"))
	if err == nil || err.Error() != "encoding patch value: json: unsupported type: chan int" {
		t.Fatalf("PatchBytes(chan) = %v, want the unchanged encoding error", err)
	}
	if _, ok := errors.AsType[*contract.Error](err); ok {
		t.Error("a programmer error became a *contract.Error")
	}
}

func TestReadLimitBoundary(t *testing.T) {
	t.Parallel()

	atLimit := writeFile(t, "at.hujson", paddedDocument(hujsonedit.DefaultMaxBytes))
	if _, err := hujsonedit.ParseFile(atLimit); err != nil {
		t.Fatalf("ParseFile at exactly DefaultMaxBytes = %v, want success", err)
	}

	overLimit := writeFile(t, "over.hujson", paddedDocument(hujsonedit.DefaultMaxBytes+1))
	want := overLimit + ": config exceeds maximum size of 16777216 bytes"
	codedtest.Assert(t, parseErr(overLimit), errcode.ConfigTooLarge, want)
	codedtest.Assert(t, leadingErr(overLimit, "pad"), errcode.ConfigTooLarge, want)
	_, err := hujsonedit.Options{}.ReadFile(overLimit)
	codedtest.Assert(t, err, errcode.ConfigTooLarge, want)
}

func TestOversizeFileIsNeverRewritten(t *testing.T) {
	t.Parallel()

	content := paddedDocument(hujsonedit.DefaultMaxBytes + 1)
	path := writeFile(t, "over.hujson", content)
	err := hujsonedit.WritePatch(path, nil, hujsonedit.PatchAdd(1, "x"))
	codedtest.Assert(t, err, errcode.ConfigTooLarge, path+": config exceeds maximum size of 16777216 bytes")
	if after, readErr := os.ReadFile(path); readErr != nil || string(after) != content {
		t.Errorf("file changed after a rejected WritePatch (read error %v)", readErr)
	}
}

func TestRaisedLimitAcceptsALargerFile(t *testing.T) {
	t.Parallel()

	content := paddedDocument(hujsonedit.DefaultMaxBytes + 1)
	path := writeFile(t, "big.hujson", content)
	options := hujsonedit.Options{MaxBytes: 2 * hujsonedit.DefaultMaxBytes}
	if _, err := options.ParseFile(path); err != nil {
		t.Fatalf("ParseFile(over the default) with a doubled limit = %v", err)
	}
	raw, err := options.ReadFile(path)
	if err != nil || !bytes.Equal(raw, []byte(content)) {
		t.Fatalf("ReadFile returned %d bytes and %v, want the file verbatim", len(raw), err)
	}
	if err = options.WritePatch(path, nil, hujsonedit.PatchAdd(1, "x")); err != nil {
		t.Fatalf("WritePatch(over the default) with a doubled limit = %v", err)
	}
}

func TestOutOfRangeLimitFailsBeforeOpening(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "never-opened.hujson")
	const want = "config max bytes must be between 0 and 1073741824"
	for _, limit := range []int64{-1, config.MaxBytesCeiling + 1} {
		t.Run(strconv.FormatInt(limit, 10), func(t *testing.T) {
			t.Parallel()
			_, err := hujsonedit.Options{MaxBytes: limit}.ParseFile(missing)
			codedtest.Assert(t, err, errcode.ConfigMaxBytesInvalid, want)
		})
	}
}

// TestParityWithAxGoConfig pins hujsonedit's codes and exit codes to ax-go's
// config.Parse on the same input, so the two bounded readers agree. The
// defaults differ on purpose, so the oversize case sets one limit for both.
func TestParityWithAxGoConfig(t *testing.T) {
	t.Parallel()

	const smallLimit = 1024
	tests := []struct {
		name     string
		content  string
		maxBytes int64
	}{
		{name: "oversize", content: paddedDocument(smallLimit + 1), maxBytes: smallLimit},
		{name: "malformed", content: malformed},
		{name: "limit above ceiling", content: "{}", maxBytes: config.MaxBytesCeiling + 1},
		{name: "negative limit", content: "{}", maxBytes: -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var opts []config.Option
			if test.maxBytes != 0 {
				opts = append(opts, config.WithMaxBytes(test.maxBytes))
			}
			var dst map[string]any
			want := envelopeOf(t, config.Parse(context.Background(), strings.NewReader(test.content), &dst, opts...))
			path := writeFile(t, "doc.hujson", test.content)
			_, err := hujsonedit.Options{MaxBytes: test.maxBytes}.ParseFile(path)
			got := envelopeOf(t, err)
			if got.ErrorCode != want.ErrorCode || got.ExitCode() != want.ExitCode() {
				t.Errorf("hujsonedit = %s/%d, config.Parse = %s/%d",
					got.ErrorCode, got.ExitCode(), want.ErrorCode, want.ExitCode())
			}
		})
	}
}

func envelopeOf(t *testing.T, err error) *contract.Error {
	t.Helper()
	envelope, ok := errors.AsType[*contract.Error](err)
	if !ok {
		t.Fatalf("%v (%T) does not unwrap to *contract.Error", err, err)
	}
	return envelope
}
