package hujsonedit

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tailscale/hujson"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/internal/coded"
)

// commentPrefix is the marker the caller supplies; callers pass only the body.
const commentPrefix = "// "

// ValidateCommentText rejects text that cannot be rendered as one HuJSON line
// comment.
//
// A carriage return or newline would close the comment and hand the
// remainder of the text to the parser as document tokens, so a single call
// could author syntax the caller never asked for. Invalid UTF-8 is rejected
// for a blunter reason: hujson.Parse fails on it, and nothing between Pack
// and WriteRaw parses again, so an invalid byte would be written into a file
// that then no longer loads.
func ValidateCommentText(text string) error {
	if strings.TrimSpace(text) == "" {
		return coded.New(errcode.CommentInvalid, errors.New("comment text must not be empty"))
	}
	if strings.ContainsAny(text, "\r\n") {
		return coded.New(errcode.CommentInvalid,
			errors.New("comment text must be one line: it must not contain a carriage return or newline"))
	}
	if !utf8.ValidString(text) {
		return coded.New(errcode.CommentInvalid, errors.New("comment text must be valid UTF-8"))
	}
	return nil
}

// PatchComment authors text as a leading "// " line comment on the node at
// segments, keeping any comments already attached there and skipping text
// that is already present.
//
// It is not an RFC 6902 operation. WritePatch applies it to the syntax tree
// after every operation in the same call, so segments name the node as it
// exists *after* the edit. A trailing "-" segment therefore resolves to the
// last element of the array it indexes — deliberately not RFC 6901's "the
// element after the last", because once the patch has run that element is
// exactly the one the operation just appended.
//
// Text is stored trimmed so that authoring, duplicate suppression, and
// LeadingComments all compare the same string. Without it, "  note  " would
// be written once and then never recognized again, stacking a copy per run.
func PatchComment(text string, segments ...string) PatchOperation {
	return PatchOperation{comment: strings.TrimSpace(text), commentSegments: slices.Clone(segments)}
}

// PatchCommentOverwrite is PatchComment except that text replaces the
// comments already attached to the node rather than being appended after
// them. A comment on the line the preceding node ends on belongs to that
// node, not this one, and is left alone — see ownCommentLines.
func PatchCommentOverwrite(text string, segments ...string) PatchOperation {
	return PatchOperation{
		comment:          strings.TrimSpace(text),
		commentSegments:  slices.Clone(segments),
		commentOverwrite: true,
	}
}

// LeadingComments returns the bodies of the "// " comments attached ahead of
// the node at segments in the document at path, in file order. resolve may
// be nil — see ResolveKey. An absent node has no comments rather than being
// an error: nothing is there to carry one yet.
//
// It exists so a caller can decide whether authoring a comment would change
// the file before it writes. That decision must be made with the same rule
// WritePatch applies, or a command reports a change for a write that changed
// nothing.
func LeadingComments(path string, resolve ResolveKey, segments ...string) ([]string, error) {
	return Options{}.LeadingComments(path, resolve, segments...)
}

// LeadingComments is the package-level LeadingComments with o's read limit.
func (o Options) LeadingComments(path string, resolve ResolveKey, segments ...string) ([]string, error) {
	document, err := o.ParseFile(path)
	if err != nil {
		return nil, err
	}
	resolved := slices.Clone(segments)
	if resolve != nil && len(resolved) > 0 {
		resolved[0] = resolve(document, resolved[0])
	}
	extra, found, err := leadingExtra(&document, resolved)
	if err != nil {
		return nil, coded.Boundary(fmt.Errorf("%s: %w", path, err))
	}
	if !found {
		return nil, nil
	}
	return ownCommentLines(*extra), nil
}

// leadingExtra returns the comment-and-whitespace slot that precedes the node
// at segments: an object member's name extra, or an array element's extra.
// The reported bool is false when the node is absent, which is a routine
// answer rather than an error — LeadingComments treats it as "no comments"
// while WritePatch treats it as a failure. An error means a segment indexed
// something that cannot be indexed.
//
// hujson.Value.Find cannot stand in for this. For an object member Find
// returns the member's *value*, whose BeforeExtra is the slot between the
// colon and the value — one hujson documents as lost when patching. A
// leading comment lives before the member *name*, so this walks to the
// parent and indexes it the way the unexported Object.beforeExtraAt and
// Array.beforeExtraAt do.
func leadingExtra(document *hujson.Value, segments []string) (*hujson.Extra, bool, error) {
	node := document
	for i, segment := range segments {
		last := i == len(segments)-1
		switch container := node.Value.(type) {
		case *hujson.Object:
			index := memberIndex(container, segment)
			if index < 0 {
				return nil, false, nil
			}
			if last {
				return &container.Members[index].Name.BeforeExtra, true, nil
			}
			node = &container.Members[index].Value
		case *hujson.Array:
			index, err := elementIndex(container, segment)
			if err != nil {
				return nil, false, coded.Errorf(errcode.ConfigPatchInvalid,
					"%s: %w", JSONPointer(segments[:i+1]...), err)
			}
			if index < 0 {
				return nil, false, nil
			}
			if last {
				return &container.Elements[index].BeforeExtra, true, nil
			}
			node = &container.Elements[index]
		default:
			return nil, false, coded.Errorf(errcode.ConfigPatchInvalid,
				"cannot index into a literal at %s", JSONPointer(segments[:i+1]...))
		}
	}
	return nil, false, nil
}

// memberIndex returns the index of name in object, or -1. Matching is exact:
// hujson resolves object names exactly. Callers that permit duplicate object
// member names in the document being patched must reject them before patching
// (see aclpolicy.checkDuplicateMembers for the reference implementation), or
// an edit may target the wrong member.
func memberIndex(object *hujson.Object, name string) int {
	for i := range object.Members {
		literal, isLiteral := object.Members[i].Name.Value.(hujson.Literal)
		if !isLiteral {
			continue
		}
		if literal.String() == name {
			return i
		}
	}
	return -1
}

// elementIndex resolves an array pointer segment. "-" names the last element
// rather than the position after it — see PatchComment for why.
func elementIndex(array *hujson.Array, segment string) (int, error) {
	if segment == "-" {
		return len(array.Elements) - 1, nil
	}
	index, err := strconv.Atoi(segment)
	if err != nil {
		return 0, fmt.Errorf("array index must be a number or %q, got %q", "-", segment)
	}
	if index < 0 || index >= len(array.Elements) {
		return -1, nil
	}
	return index, nil
}

// ownCommentLines returns the bodies of the "// " comments in extra that
// belong to the node extra precedes.
//
// Only lines after the slot's first newline count. hujson attributes a line
// comment that starts on the slot's first line, with no blank line dividing
// it, to the *previous* node — it is that node's trailing comment. Counting
// it here would let a neighbour's note suppress an identical one on this
// node, and would let an overwrite delete a comment describing a different
// entry.
//
// Bodies are trimmed of surrounding space so a hand-written "//note" is not
// re-authored as "// note", and so a rerun still matches after Format has
// stripped the trailing whitespace from its own output.
func ownCommentLines(extra hujson.Extra) []string {
	_, rest, found := bytes.Cut(extra, []byte("\n"))
	if !found {
		return nil
	}
	var lines []string
	for line := range strings.SplitSeq(string(rest), "\n") {
		body, ok := strings.CutPrefix(strings.TrimSpace(line), "//")
		if !ok {
			continue
		}
		lines = append(lines, strings.TrimSpace(body))
	}
	return lines
}

// appendCommentLine appends "// text" to the slot preceding a node.
//
// The guarded newline is load-bearing, not cosmetic. An element inserted
// into a compact array arrives with an empty slot, so appending without it
// renders "},// text" — which hujson then reads back as the *previous*
// element's trailing comment, silently retitling the entry above. The
// condition is the one hujson's own injectLeadingComments uses.
//
// No trailing indentation is appended on purpose: WritePatch calls Format
// before Pack, and Format re-indents every comment to its depth and
// re-appends the closing indent.
func appendCommentLine(extra *hujson.Extra, text string) {
	if i := bytes.LastIndexByte(*extra, '\n'); i < 0 || notAllWhitespace((*extra)[i:]) {
		*extra = append(*extra, '\n')
	}
	*extra = append(*extra, commentPrefix+text+"\n"...)
}

// replaceCommentLines drops the comments belonging to the node extra
// precedes and leaves only "// text". Everything up to and including the
// first newline is kept, which is exactly the region ownCommentLines
// attributes to the preceding node.
func replaceCommentLines(extra *hujson.Extra, text string) {
	if i := bytes.IndexByte(*extra, '\n'); i >= 0 {
		*extra = (*extra)[:i+1]
	}
	appendCommentLine(extra, text)
}

// notAllWhitespace mirrors hujson's unexported Extra.hasComment: in a slot
// that by construction holds only whitespace and comments, "not all
// whitespace" is exactly "has a comment".
func notAllWhitespace(b []byte) bool {
	return len(bytes.TrimLeft(b, " \t\r\n")) > 0
}
