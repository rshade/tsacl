// Package aclpolicy provides shared policy-file I/O using Tailscale's public
// ACL schema types.
//
// Rule-syntax skips and indeterminate evaluations deliberately describe
// different scopes. A skip says the policy contains an unreadable element and
// is collected over the whole file. An indeterminate result says one particular
// query reached that element after every readable field on its rule matched.
// A policy may therefore have skips while every evaluated query remains settled.
package aclpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/tailscale/hujson"
	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/pkg/policycore/hujsonedit"
)

// Files reads and writes policy and lint-config files under one read limit,
// so every operator-supplied HuJSON input a command touches is bounded the
// same way. The zero value applies hujsonedit's default limit (16 MiB); the
// package-level functions use it.
type Files struct {
	Limits hujsonedit.Options
}

// PatchOperation is a schema-agnostic HuJSON patch mechanic that lives in
// policycore/hujsonedit; this is a type alias so every existing call site in
// this package and cmd/tsacl keeps compiling unchanged. See
// hujsonedit's package doc for why the mechanics moved out. PatchAdd,
// PatchRemove, JSONPointer, and WriteRaw below are the matching function
// re-exports.
type PatchOperation = hujsonedit.PatchOperation

// PatchAdd constructs an RFC 6902 add operation; see hujsonedit.PatchAdd.
func PatchAdd(value any, segments ...string) PatchOperation {
	return hujsonedit.PatchAdd(value, segments...)
}

// PatchRemove constructs an RFC 6902 remove operation; see hujsonedit.PatchRemove.
func PatchRemove(segments ...string) PatchOperation {
	return hujsonedit.PatchRemove(segments...)
}

// PatchPruneEmpty constructs a comment-aware prune of an emptied container; see
// hujsonedit.PatchPruneEmpty.
func PatchPruneEmpty(segments ...string) PatchOperation {
	return hujsonedit.PatchPruneEmpty(segments...)
}

// JSONPointer returns an RFC 6901 pointer for path segments; see hujsonedit.JSONPointer.
func JSONPointer(segments ...string) string {
	return hujsonedit.JSONPointer(segments...)
}

// WriteRaw atomically writes data to path; see hujsonedit.WriteRaw.
func WriteRaw(path string, data []byte) error {
	return hujsonedit.WriteRaw(path, data)
}

// policySourceField and policyDestinationField name the two selector members
// that appear alike in grants, ACL entries, SSH rules, and tests. They are
// declared once for the package so a reference walk and a merge normalizer
// cannot disagree about the spelling.
const (
	policySourceField      = "src"
	policyDestinationField = "dst"
	policyUsersField       = "users"
	policyPortsField       = "ports"
	// policyAppField is typed under nodeAttrs and opaque under grants, so the
	// merge normalizer has to tell the two apart by section.
	policyAppField = "app"
)

// Policy extends the pinned Tailscale client schema with policy-file fields the
// client does not yet model.
//
// SSH shadows the promoted ACL.SSH field so acceptEnv can be preserved. Policy.SSH
// remains the lossless source of truth; ACL.SSH is only a read-only evaluator
// mirror. Typed SSH authoring validates against Policy.SSH but commits through
// hujson.Patch on the raw document, so it never round-trips this incomplete
// client shape and cannot drop acceptEnv or sshTests.
type Policy struct {
	tailscale.ACL

	SSH      []SSHRule `json:"ssh,omitempty"`
	SSHTests []SSHTest `json:"sshTests,omitempty"`

	// sshCheckPeriodPresent records syntax that the pinned ACLSSH type collapses
	// into a zero value. It is used only for semantic SSH edit identity.
	sshCheckPeriodPresent []bool
}

// resolveTopLevelKey returns the name document actually uses for the top-level
// policy key canonical, which may differ in case.
//
// Load decodes through encoding/json, which matches struct fields
// case-insensitively, so a policy written in Tailscale's legacy capitalized
// style ("Grants", "TagOwners") validates and populates the typed Policy.
// hujson.Patch matches object names exactly. Without this bridge a pointer
// built from the canonical lowercase name misses the member the typed policy
// was decoded from, and the edit fails with "value not found". Resolving here
// keeps the file's own spelling instead of renaming the operator's keys.
//
// An absent key resolves to canonical so a newly created member is spelled the
// documented way.
func resolveTopLevelKey(document hujson.Value, canonical string) string {
	object, ok := document.Value.(*hujson.Object)
	if !ok {
		return canonical
	}
	for i := range object.Members {
		literal, isLiteral := object.Members[i].Name.Value.(hujson.Literal)
		if !isLiteral {
			continue
		}
		if name := literal.String(); strings.EqualFold(name, canonical) {
			return name
		}
	}
	return canonical
}

// checkDuplicateMembers rejects a policy containing the same object member name
// twice at any depth.
//
// Duplicates are not merely untidy here: encoding/json resolves them last-wins
// while hujson resolves them first-wins, so a typed edit would validate against
// one member and patch a different one — reporting success while destroying
// policy the operator was never shown. Refusing the file is the only answer
// that cannot silently pick the wrong one.
func checkDuplicateMembers(document hujson.Value) error {
	switch value := document.Value.(type) {
	case *hujson.Object:
		seen := make(map[string]struct{}, len(value.Members))
		for i := range value.Members {
			literal, isLiteral := value.Members[i].Name.Value.(hujson.Literal)
			if !isLiteral {
				continue
			}
			name := literal.String()
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate object member %q", name)
			}
			seen[name] = struct{}{}
			if err := checkDuplicateMembers(value.Members[i].Value); err != nil {
				return fmt.Errorf("%q: %w", name, err)
			}
		}
	case *hujson.Array:
		for i := range value.Elements {
			if err := checkDuplicateMembers(value.Elements[i]); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
		}
	}
	return nil
}

// ReadRaw reads path under f's limit and verifies that it contains
// syntactically valid HuJSON, returning the bytes exactly as read.
func (f Files) ReadRaw(path string) ([]byte, error) {
	b, _, err := f.ReadParsed(path)
	return b, err
}

// ReadParsed is ReadRaw that also returns the syntax tree it parsed, so a
// caller that needs both pays for one parse. The tree aliases the returned
// bytes, and hujson's Format, Minimize, Standardize, and Patch rewrite it in
// place: finish with the bytes before transforming the tree.
func (f Files) ReadParsed(path string) ([]byte, hujson.Value, error) {
	b, err := f.Limits.ReadFile(path)
	if err != nil {
		return nil, hujson.Value{}, err
	}
	tree, err := hujsonedit.Parse(path, b)
	if err != nil {
		return nil, hujson.Value{}, err
	}
	return b, tree, nil
}

// Normalize reads path and returns its contents as standard JSON. HuJSON-only
// comments and trailing commas are replaced with whitespace, preserving the
// document's data while making the result consumable by strict JSON tools.
// The source file is never modified.
//
// Duplicate object members are rejected for the reason checkDuplicateMembers
// gives, sharpened by where this output goes: hujson resolves duplicates
// first-wins, while encoding/json, jq, and the rest of the strict-JSON tooling
// this command feeds resolve them last-wins. Emitting the document would answer
// an operator with the member tsacl itself discards, so normalize refuses the
// file exactly as Load does.
func Normalize(path string) ([]byte, error) { return Files{}.Normalize(path) }

// Normalize is the package-level Normalize under f's read limit.
func (f Files) Normalize(path string) ([]byte, error) {
	raw, err := f.ReadRaw(path)
	if err != nil {
		return nil, err
	}
	document, err := hujsonedit.Parse(path, raw)
	if err != nil {
		return nil, err
	}
	if err = checkDuplicateMembers(document); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	document.Standardize()
	return document.Pack(), nil
}

// Load reads a JSON or HuJSON policy into the local Policy type. Unknown fields
// are rejected so an edit cannot silently discard policy data that neither the
// pinned Tailscale client nor the local extensions model. Duplicate object
// members are rejected for the same reason — see checkDuplicateMembers.
func Load(path string) (*Policy, error) { return Files{}.Load(path) }

// Load is the package-level Load under f's read limit.
func (f Files) Load(path string) (*Policy, error) {
	raw, err := f.ReadRaw(path)
	if err != nil {
		return nil, err
	}
	return LoadBytes(path, raw)
}

// LoadBytes decodes a policy from bytes the caller already holds. It exists for
// a caller that must know exactly which bytes produced a verdict: tsacl's
// watch loop content-addresses every run, and hashing its own read while Load
// took a second would let it report a digest for bytes it never evaluated. name
// is used only in error messages.
func LoadBytes(name string, raw []byte) (*Policy, error) {
	document, err := hujsonedit.Parse(name, raw)
	if err != nil {
		return nil, err
	}
	if err = checkDuplicateMembers(document); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err = checkUnknownPolicyKeys(document); err != nil {
		return nil, fmt.Errorf("decoding %s as a Tailscale policy: %w", name, err)
	}
	var policy Policy
	if err = decodeHuJSON(name, raw, "a Tailscale policy", &policy); err != nil {
		return nil, err
	}

	// Keep ACL.SSH populated so a read-only evaluator handed &policy.ACL never
	// sees a false empty policy. SSH authoring does not marshal this mirror:
	// its typed validation is followed by a raw hujson.Patch, which preserves
	// fields the pinned ACLSSH cannot represent, including acceptEnv.
	policy.ACL.SSH = policy.sshRules()
	policy.sshCheckPeriodPresent = sshCheckPeriodPresence(document)
	return &policy, nil
}

func sshCheckPeriodPresence(document hujson.Value) []bool {
	object, ok := document.Value.(*hujson.Object)
	if !ok {
		return nil
	}
	sshName := resolveTopLevelKey(document, "ssh")
	for i := range object.Members {
		literal, isLiteral := object.Members[i].Name.Value.(hujson.Literal)
		if !isLiteral || literal.String() != sshName {
			continue
		}
		array, isArray := object.Members[i].Value.Value.(*hujson.Array)
		if !isArray {
			return nil
		}
		presence := make([]bool, len(array.Elements))
		for index := range array.Elements {
			entry, isEntry := array.Elements[index].Value.(*hujson.Object)
			if !isEntry {
				continue
			}
			for memberIndex := range entry.Members {
				name, isName := entry.Members[memberIndex].Name.Value.(hujson.Literal)
				if isName && strings.EqualFold(name.String(), "checkPeriod") {
					presence[index] = true
					break
				}
			}
		}
		return presence
	}
	return nil
}

// decodeHuJSON standardizes and strictly decodes one already-read HuJSON
// document. Policy and lint-config loading share this path so trailing-value
// behavior and the strictness of nested unknown fields cannot drift between the
// two local file formats.
//
// Top-level unknown fields no longer share it: checkUnknownPolicyKeys reports
// every one of a policy's at once before this runs. LintConfig deliberately
// does not get that pre-pass -- it has a single top-level key, so the
// misspelling worth catching there is nested, where both formats still fail
// through DisallowUnknownFields one field at a time.
func decodeHuJSON(name string, raw []byte, description string, destination any) error {
	standard, err := hujson.Standardize(raw)
	if err != nil {
		return fmt.Errorf("standardizing %s: %w", name, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(standard))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(destination); err != nil {
		return fmt.Errorf("decoding %s as %s: %w", name, description, err)
	}
	if err = ensureEOF(decoder); err != nil {
		return fmt.Errorf("decoding %s as %s: %w", name, description, err)
	}
	return nil
}

// sshRules projects Policy.SSH onto the pinned client's shape. It is the only
// conversion from Policy.SSH, so a caller that needs SSH rules can derive them
// from the source of truth rather than trusting ACL.SSH, which is a mirror that
// only LoadBytes populates.
func (p *Policy) sshRules() []tailscale.ACLSSH {
	rules := make([]tailscale.ACLSSH, len(p.SSH))
	for i := range p.SSH {
		rules[i] = p.SSH[i].ACLSSH
	}
	return rules
}

// checkSSHSourceOfTruth refuses to encode a Policy whose SSH rules live only in
// the embedded ACL.SSH mirror. Policy.SSH shadows that field, so such a Policy
// marshals with no "ssh" key at all — the one way this package can silently drop
// policy data. Nothing builds that state today, so this guards a future caller
// who copies Load's mirror assignment in reverse; it is not a runtime path.
//
// It fires only on the unambiguous data-loss case. Any other divergence between
// the two still encodes Policy.SSH, which is the documented source of truth.
func (p *Policy) checkSSHSourceOfTruth() error {
	if len(p.SSH) == 0 && len(p.ACL.SSH) != 0 {
		return errors.New(
			"ssh rules are set only on the embedded ACL.SSH mirror, which Policy.SSH shadows; " +
				"set Policy.SSH instead",
		)
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple JSON values")
}

// Write atomically writes policy as indented standard JSON. Existing file
// permissions are retained; new files are created with mode 0644.
func Write(path string, policy *Policy) error {
	if err := policy.checkSSHSourceOfTruth(); err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	b, err := json.MarshalIndent(policy, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	b = append(b, '\n')
	return WriteRaw(path, b)
}

// WritePatch atomically applies comment-preserving RFC 6902 operations to a
// JSON or HuJSON policy, then authors any comments those operations carry.
// Callers must Load the policy first so unknown fields are rejected before an
// edit can be written.
//
// The patch/comment mechanics are schema-agnostic and live in
// policycore/hujsonedit; this wrapper supplies resolveTopLevelKey so a policy
// written in Tailscale's legacy capitalized style still resolves.
func WritePatch(path string, operations ...PatchOperation) error {
	return Files{}.WritePatch(path, operations...)
}

// WritePatch is the package-level WritePatch under f's read limit; a policy
// over the limit is never rewritten.
func (f Files) WritePatch(path string, operations ...PatchOperation) error {
	return f.Limits.WritePatch(path, resolveTopLevelKey, operations...)
}
