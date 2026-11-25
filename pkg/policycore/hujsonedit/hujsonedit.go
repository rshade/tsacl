// Package hujsonedit provides schema-agnostic, comment-preserving RFC 6902
// edits to HuJSON documents: build PatchOperation values with PatchAdd,
// PatchRemove, PatchComment, and PatchCommentOverwrite, then apply them with
// WritePatch to a file or with PatchBytes to a document held in memory. It
// carries no knowledge of any particular document's fields — callers own
// that; this package owns only the AST/patch mechanics.
//
// Extracted from tsacl/internal/aclpolicy, which found these mechanics
// were already entirely free of ACL-specific logic. The one schema-specific
// concern that stayed behind is legacy/alternate top-level key spellings —
// see ResolveKey.
package hujsonedit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rshade/ax-go/config"
	"github.com/tailscale/hujson"

	"github.com/rshade/tsacl/pkg/policycore/errcode"
	"github.com/rshade/tsacl/pkg/policycore/internal/coded"
)

// defaultFileMode is applied to files that do not already exist.
const defaultFileMode os.FileMode = 0o644

// PatchOperation is one comment-preserving document edit: an RFC 6902
// operation, an authored comment, or both. Construct operations with PatchAdd
// and PatchRemove so the encoded patch has exactly the fields required by
// that operation, and with PatchComment or PatchCommentOverwrite to author a
// comment.
//
// Operations carry path segments rather than a rendered pointer because
// WritePatch resolves the first segment against the document it is about to
// patch via the caller-supplied ResolveKey — see WritePatch.
//
// A comment carries its own segments because it names the node as it exists
// *after* every operation in the call has been applied, which is not always
// the node the operation targeted: creating an absent block patches the
// block, while the comment belongs to the entry inside it.
type PatchOperation struct {
	op       string
	segments []string
	value    any
	hasValue bool
	prune    bool

	comment          string
	commentSegments  []string
	commentOverwrite bool
}

// PatchAdd constructs an RFC 6902 add operation targeting segments. Per RFC
// 6902, add also replaces an existing object member at that location.
func PatchAdd(value any, segments ...string) PatchOperation {
	return PatchOperation{op: "add", segments: segments, value: value, hasValue: true}
}

// PatchRemove constructs an RFC 6902 remove operation targeting segments.
func PatchRemove(segments ...string) PatchOperation {
	return PatchOperation{op: "remove", segments: segments}
}

// PatchPruneEmpty constructs an operation that deletes the object member at
// segments, but only when its value is an empty object or array and no comment
// is attached to the member, its value, or the container's interior. It runs
// after every RFC 6902 operation in the same call, so a removal that empties a
// container can be followed by its prune. A container that still holds data, or
// that carries a comment, is left alone: the prune never discards authored
// text. List inner containers before the outer ones that hold them.
func PatchPruneEmpty(segments ...string) PatchOperation {
	return PatchOperation{op: "", segments: segments, prune: true}
}

// JSONPointer returns an RFC 6901 pointer for path segments. Escaping each
// segment here keeps user-controlled names from changing the location an
// edit targets.
func JSONPointer(segments ...string) string {
	var pointer strings.Builder
	for _, segment := range segments {
		pointer.WriteByte('/')
		segment = strings.ReplaceAll(segment, "~", "~0")
		segment = strings.ReplaceAll(segment, "/", "~1")
		pointer.WriteString(segment)
	}
	return pointer.String()
}

// ResolveKey lets a caller bridge alternate top-level key spellings (e.g. a
// schema with legacy-capitalized field names, matched case-insensitively by
// encoding/json but not by hujson.Value.Patch, which matches exactly) before
// a path's first segment is resolved against the parsed document. Pass nil
// when the schema has no such aliasing — the first segment is then used
// exactly as authored.
type ResolveKey func(document hujson.Value, canonical string) string

// DefaultMaxBytes is the read limit of the zero [Options]: 16 MiB. It is
// larger than ax-go's 1 MiB config.DefaultMaxBytes because a tailnet policy is
// not a tool config, and production policies of several megabytes exist.
const DefaultMaxBytes int64 = 16 << 20

// Options configures how this package reads files. The zero value reads
// with the DefaultMaxBytes limit, and the package-level ParseFile,
// WritePatch, and LeadingComments use it.
type Options struct {
	// MaxBytes caps every file read, matching ax-go's config.WithMaxBytes up
	// to config.MaxBytesCeiling. Zero means DefaultMaxBytes. A file of
	// exactly MaxBytes is accepted; a larger one fails with config_too_large.
	// A negative value, or one above the ceiling, fails with
	// config_max_bytes_invalid before the file is opened.
	MaxBytes int64
}

func (o Options) maxBytes() (int64, error) {
	switch {
	case o.MaxBytes == 0:
		return DefaultMaxBytes, nil
	case o.MaxBytes < 0 || o.MaxBytes > config.MaxBytesCeiling:
		return 0, coded.Errorf(errcode.ConfigMaxBytesInvalid,
			"config max bytes must be between 0 and %d", config.MaxBytesCeiling)
	default:
		return o.MaxBytes, nil
	}
}

// ReadFile returns the bytes of path, unparsed, under the read limit, so a
// caller that decodes the document itself bounds it exactly as ParseFile
// does. A failure to open or read the file is returned as the underlying
// error, which still satisfies [errors.Is](err, fs.ErrNotExist) for a missing
// file.
func (o Options) ReadFile(path string) ([]byte, error) {
	limit, err := o.maxBytes()
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	// One byte past the limit is the tripwire: reading it proves the file is
	// too large without reading the rest.
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, coded.Errorf(errcode.ConfigTooLarge,
			"%s: config exceeds maximum size of %d bytes", path, limit)
	}
	return data, nil
}

// ParseFile reads path under the read limit and parses it as HuJSON (a
// superset of JSON, so plain JSON files parse too). A document that does not
// parse fails with config_invalid.
func (o Options) ParseFile(path string) (hujson.Value, error) {
	data, err := o.ReadFile(path)
	if err != nil {
		return hujson.Value{}, err
	}
	return Parse(path, data)
}

// Parse parses a document the caller already holds, such as bytes from
// [Options.ReadFile] that the caller also needs verbatim. name appears only in
// the error text, which matches ParseFile's for a file at that path: a
// document that does not parse fails with config_invalid.
func Parse(name string, data []byte) (hujson.Value, error) {
	value, err := hujson.Parse(data)
	if err != nil {
		return hujson.Value{}, coded.Errorf(errcode.ConfigInvalid, "%s: %w", name, err)
	}
	return value, nil
}

// ParseFile is [Options.ParseFile] with the default read limit.
func ParseFile(path string) (hujson.Value, error) { return Options{}.ParseFile(path) }

// WritePatch atomically applies comment-preserving RFC 6902 operations to a
// JSON or HuJSON document at path, then authors any comments those
// operations carry. resolve may be nil — see ResolveKey.
//
// It is PatchBytes bracketed by a read and an atomic write, so the two
// cannot disagree about what an operation means. Nothing is written unless
// the whole patch succeeded: an operation that fails leaves the file exactly
// as it was.
func WritePatch(path string, resolve ResolveKey, operations ...PatchOperation) error {
	return Options{}.WritePatch(path, resolve, operations...)
}

// WritePatch is the package-level WritePatch with o's read limit. A file over
// the limit is never rewritten.
func (o Options) WritePatch(path string, resolve ResolveKey, operations ...PatchOperation) error {
	data, err := o.ReadFile(path)
	if err != nil {
		return err
	}
	patched, err := PatchBytes(data, resolve, operations...)
	if err != nil {
		return coded.Boundary(fmt.Errorf("%s: %w", path, err))
	}
	return WriteRaw(path, patched)
}

// PatchBytes applies comment-preserving RFC 6902 operations to the JSON or
// HuJSON document in data, authors any comments those operations carry, and
// returns the reformatted result. data is not modified. resolve may be nil —
// see ResolveKey.
//
// Operations apply in order, then every comment, then the document is
// reformatted. Comments come last because a comment names its node as that
// node exists after the edit — see PatchComment.
//
// Patching in memory is what lets a caller decide whether an edit is any
// good before it reaches the filesystem, rather than writing it, re-reading
// to find out, and undoing it when it was not: a rejected candidate is
// simply dropped, so there is no window in which the file holds it and no
// restore that can itself fail.
func PatchBytes(data []byte, resolve ResolveKey, operations ...PatchOperation) ([]byte, error) {
	patched, err := patchBytes(data, resolve, operations)
	if err != nil {
		return nil, coded.Boundary(err)
	}
	return patched, nil
}

func patchBytes(data []byte, resolve ResolveKey, operations []PatchOperation) ([]byte, error) {
	value, err := hujson.Parse(data)
	if err != nil {
		return nil, coded.New(errcode.ConfigInvalid, err)
	}
	// json.RawMessage rather than any: omitempty must track hasValue exactly.
	// On an any field omitempty omits only a nil interface, so PatchAdd(nil)
	// would encode an add with no "value" member, which RFC 6902 forbids. A
	// RawMessage is empty only when nothing was marshaled into it.
	type encodedOperation struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value,omitempty"`
	}
	// A comment-only operation has no RFC 6902 counterpart. It must be skipped
	// rather than encoded: a zero-valued entry reaches hujson as
	// {"op":"","path":""} and fails the whole patch. The slice stays non-nil
	// so an all-comment call still marshals as [], which hujson accepts as an
	// empty operation list.
	patch := make([]encodedOperation, 0, len(operations))
	for _, operation := range operations {
		if operation.op == "" {
			continue
		}
		segments := slices.Clone(operation.segments)
		if resolve != nil && len(segments) > 0 {
			segments[0] = resolve(value, segments[0])
		}
		encoded := encodedOperation{Op: operation.op, Path: JSONPointer(segments...)}
		if operation.hasValue {
			raw, valueErr := json.Marshal(operation.value)
			if valueErr != nil {
				return nil, fmt.Errorf("encoding patch value: %w", valueErr)
			}
			encoded.Value = raw
		}
		patch = append(patch, encoded)
	}
	// Indent inserted composite values so a document previously emitted with
	// standard indentation keeps that layout. HuJSON's formatter will still
	// retain compact layout where the surrounding edited region is compact.
	rawPatch, err := json.MarshalIndent(patch, "", "\t")
	if err != nil {
		return nil, fmt.Errorf("encoding patch: %w", err)
	}
	if err = value.Patch(rawPatch); err != nil {
		return nil, coded.Errorf(errcode.ConfigPatchInvalid, "applying patch: %w", err)
	}
	if err = applyPrunes(&value, resolve, operations); err != nil {
		return nil, err
	}
	if err = applyComments(&value, resolve, operations); err != nil {
		return nil, err
	}
	value.Format()
	return value.Pack(), nil
}

// applyPrunes deletes each PatchPruneEmpty target that is an empty,
// comment-free container. A target that does not resolve is skipped: the
// prune is opportunistic and an absent member needs no removal.
func applyPrunes(value *hujson.Value, resolve ResolveKey, operations []PatchOperation) error {
	for _, operation := range operations {
		if !operation.prune || len(operation.segments) == 0 {
			continue
		}
		segments := slices.Clone(operation.segments)
		if resolve != nil {
			segments[0] = resolve(*value, segments[0])
		}
		if !prunable(value, segments) {
			continue
		}
		raw, err := json.Marshal([]map[string]string{{"op": "remove", "path": JSONPointer(segments...)}})
		if err != nil {
			return fmt.Errorf("encoding prune: %w", err)
		}
		if err = value.Patch(raw); err != nil {
			return coded.Errorf(errcode.ConfigPatchInvalid, "pruning %s: %w", JSONPointer(segments...), err)
		}
	}
	return nil
}

// prunable reports whether the object member at segments holds an empty object
// or array with no comment anywhere around it.
func prunable(document *hujson.Value, segments []string) bool {
	node := document
	var member *hujson.ObjectMember
	for _, segment := range segments {
		object, ok := node.Value.(*hujson.Object)
		if !ok {
			return false
		}
		index := memberIndex(object, segment)
		if index < 0 {
			return false
		}
		member = &object.Members[index]
		node = &member.Value
	}
	if member == nil {
		return false
	}
	extras := []hujson.Extra{
		member.Name.BeforeExtra, member.Name.AfterExtra, member.Value.BeforeExtra, member.Value.AfterExtra,
	}
	if slices.ContainsFunc(extras, hasComment) {
		return false
	}
	switch container := member.Value.Value.(type) {
	case *hujson.Object:
		return len(container.Members) == 0 && !hasComment(container.AfterExtra)
	case *hujson.Array:
		return len(container.Elements) == 0 && !hasComment(container.AfterExtra)
	default:
		return false
	}
}

func hasComment(extra hujson.Extra) bool {
	return bytes.Contains(extra, []byte("//")) || bytes.Contains(extra, []byte("/*"))
}

// applyComments authors each operation's comment onto the already-patched
// document.
//
// The top-level key is resolved against the post-patch document so an
// aliased key still resolves and a key the patch just created resolves to
// its own spelling. A target that does not resolve is an error rather than a
// silent skip, so the edit fails closed: hujson leaves a partially patched
// value behind on error, but PatchBytes discards it and returns no document,
// so no caller can write it.
func applyComments(value *hujson.Value, resolve ResolveKey, operations []PatchOperation) error {
	for _, operation := range operations {
		if operation.comment == "" {
			continue
		}
		if err := ValidateCommentText(operation.comment); err != nil {
			return fmt.Errorf("commenting: %w", err)
		}
		segments := slices.Clone(operation.commentSegments)
		if resolve != nil && len(segments) > 0 {
			segments[0] = resolve(*value, segments[0])
		}
		extra, found, err := leadingExtra(value, segments)
		if err != nil {
			return fmt.Errorf("commenting: %w", err)
		}
		if !found {
			return coded.Errorf(errcode.ConfigPatchInvalid, "commenting: no node at %s", JSONPointer(segments...))
		}
		switch {
		case operation.commentOverwrite:
			replaceCommentLines(extra, operation.comment)
		case !slices.Contains(ownCommentLines(*extra), operation.comment):
			appendCommentLine(extra, operation.comment)
		}
	}
	return nil
}

// WriteRaw atomically writes data to path. Existing file permissions are
// retained; new files are created with mode 0644.
func WriteRaw(path string, data []byte) error {
	mode := defaultFileMode
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()

	if err = temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err = temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return nil
}
