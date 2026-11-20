package aclpolicy

import "github.com/rshade/tsacl/pkg/policycore/hujsonedit"

// PatchComment, PatchCommentOverwrite, and ValidateCommentText are
// schema-agnostic HuJSON comment-authoring mechanics that live in
// policycore/hujsonedit; these are thin re-exports so every existing call
// site in this package and cmd/tsacl keeps compiling unchanged.

// PatchComment authors text as a leading comment; see hujsonedit.PatchComment.
func PatchComment(text string, segments ...string) PatchOperation {
	return hujsonedit.PatchComment(text, segments...)
}

// PatchCommentOverwrite replaces the comments already attached to a node; see
// hujsonedit.PatchCommentOverwrite.
func PatchCommentOverwrite(text string, segments ...string) PatchOperation {
	return hujsonedit.PatchCommentOverwrite(text, segments...)
}

// ValidateCommentText rejects text that cannot be rendered as one HuJSON line
// comment; see hujsonedit.ValidateCommentText.
func ValidateCommentText(text string) error {
	return hujsonedit.ValidateCommentText(text)
}

// LeadingComments returns the bodies of the "// " comments attached ahead of
// the node at segments in the policy at path, in file order. It supplies
// resolveTopLevelKey so a policy written in Tailscale's legacy capitalized
// style still resolves — see hujsonedit.LeadingComments for the rest of the
// contract.
func LeadingComments(path string, segments ...string) ([]string, error) {
	return Files{}.LeadingComments(path, segments...)
}

// LeadingComments is the package-level LeadingComments under f's read limit.
func (f Files) LeadingComments(path string, segments ...string) ([]string, error) {
	return f.Limits.LeadingComments(path, resolveTopLevelKey, segments...)
}
