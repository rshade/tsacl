package aclpolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tailscale/hujson"
)

// MergePair deep-merges addPath into basePath and returns formatted HuJSON.
// Comments and formatting attached to the base policy are retained.
func MergePair(basePath, addPath string) ([]byte, error) {
	return Files{}.MergePair(basePath, addPath)
}

// MergePair is the package-level MergePair, reading both inputs under f's
// limit.
func (f Files) MergePair(basePath, addPath string) ([]byte, error) {
	base, err := f.Limits.ParseFile(basePath)
	if err != nil {
		return nil, err
	}
	add, err := f.Limits.ParseFile(addPath)
	if err != nil {
		return nil, err
	}
	if err = MergeInto(&base, &add); err != nil {
		return nil, err
	}
	base.Format()
	return base.Pack(), nil
}

// MergeDirectories deep-merges ACL files from dirs and returns standard JSON,
// the selected input paths, and any error. The output path is excluded so a
// generated acl.json is not merged again on subsequent runs.
func MergeDirectories(dirs []string, outputPath string) ([]byte, []string, error) {
	return Files{}.MergeDirectories(dirs, outputPath)
}

// MergeDirectories is the package-level MergeDirectories, reading every
// fragment under f's limit.
func (f Files) MergeDirectories(dirs []string, outputPath string) ([]byte, []string, error) {
	paths, err := ACLFilesInDirectories(dirs, outputPath)
	if err != nil {
		return nil, nil, err
	}
	if len(paths) == 0 {
		return nil, nil, fmt.Errorf(
			"no ACL files found in %s; merge reads files named acl.json, acl.hujson, *.acl.json or *.acl.hujson",
			strings.Join(dirs, ", "),
		)
	}

	merged, err := f.Limits.ParseFile(paths[0])
	if err != nil {
		return nil, nil, err
	}
	for _, path := range paths[1:] {
		value, parseErr := f.Limits.ParseFile(path)
		if parseErr != nil {
			return nil, nil, parseErr
		}
		if mergeErr := MergeInto(&merged, &value); mergeErr != nil {
			return nil, nil, fmt.Errorf("merging %s: %w", path, mergeErr)
		}
	}

	merged.Standardize()
	merged.Format()
	return merged.Pack(), paths, nil
}

// MergeInto recursively deep-merges src into dst. Objects merge by key,
// arrays append semantically distinct elements, and scalar or mismatched
// values are replaced by src.
func MergeInto(dst, src *hujson.Value) error {
	return mergeInto(dst, src, "")
}

// mergeInto carries the top-level policy section the recursion is inside, so
// selector normalization can tell nodeAttrs[].app (typed, selector-bearing)
// from grants[].app (an opaque third-party capability payload). See
// normalizeSelectorOrder.
//
//nolint:gocognit // recursive deep-merge over the object/array/scalar cases; the branch count is the algorithm itself.
func mergeInto(dst, src *hujson.Value, section string) error {
	switch destination := dst.Value.(type) {
	case *hujson.Object:
		source, ok := src.Value.(*hujson.Object)
		if !ok {
			dst.Value = src.Value
			return nil
		}
		index := make(map[string]int, len(destination.Members))
		for i := range destination.Members {
			key, err := memberKey(&destination.Members[i])
			if err != nil {
				return err
			}
			if _, exists := index[key]; !exists {
				index[key] = i
			}
		}
		for i := range source.Members {
			sourceMember := &source.Members[i]
			key, err := memberKey(sourceMember)
			if err != nil {
				return err
			}
			if idx, exists := index[key]; exists {
				// The outermost object is the policy document, so its member
				// names are the section names; below that the section is fixed.
				childSection := section
				if childSection == "" {
					childSection = key
				}
				if mergeErr := mergeInto(
					&destination.Members[idx].Value, &sourceMember.Value, childSection); mergeErr != nil {
					return mergeErr
				}
			} else {
				index[key] = len(destination.Members)
				destination.Members = append(destination.Members, *sourceMember)
			}
		}
	case *hujson.Array:
		source, ok := src.Value.(*hujson.Array)
		if !ok {
			dst.Value = src.Value
			return nil
		}
		seen := make(map[string]struct{}, len(destination.Elements)+len(source.Elements))
		for i := range destination.Elements {
			key, err := semanticValueKey(&destination.Elements[i], section)
			if err != nil {
				return err
			}
			seen[key] = struct{}{}
		}
		for i := range source.Elements {
			key, err := semanticValueKey(&source.Elements[i], section)
			if err != nil {
				return err
			}
			if _, exists := seen[key]; exists {
				continue
			}
			destination.Elements = append(destination.Elements, source.Elements[i])
			seen[key] = struct{}{}
		}
	default:
		dst.Value = src.Value
	}
	return nil
}

// semanticValueKey returns a canonical JSON representation that ignores
// HuJSON comments, whitespace, trailing commas, object member order, and the
// order of values in ACL selector fields.
func semanticValueKey(value *hujson.Value, section string) (string, error) {
	standard, err := hujson.Standardize(value.Pack())
	if err != nil {
		return "", fmt.Errorf("standardizing array element: %w", err)
	}

	var decoded any
	decoder := json.NewDecoder(strings.NewReader(string(standard)))
	decoder.UseNumber()
	if err = decoder.Decode(&decoded); err != nil {
		return "", fmt.Errorf("decoding array element: %w", err)
	}
	normalizeSelectorOrder(decoded, section)
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return "", fmt.Errorf("canonicalizing array element: %w", err)
	}
	return string(canonical), nil
}

// normalizeSelectorOrder treats ACL selector lists as sets while leaving all
// other JSON arrays order-sensitive. This makes grants and SSH rules compare
// equal when a hand-edited policy lists the same selectors in another order.
//
// section is the top-level policy key the element came from, because one
// member name means different things in different sections. nodeAttrs[].app is
// the pinned NodeAttrGrantApp, whose connectors and domains are selector lists;
// grants[].app is map[string][]map[string]any, an opaque payload owned by a
// third-party capability. A member named target or domains inside that payload
// carries the capability's meaning, and its order has to survive the merge —
// sorting it would make two distinct grants compare equal and silently drop one.
func normalizeSelectorOrder(value any, section string) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if strings.EqualFold(key, policyAppField) && !isNodeAttrsSection(section) {
				continue
			}
			normalizeSelectorOrder(child, section)
			if !isUnorderedSelectorField(key, section) {
				continue
			}
			items, ok := child.([]any)
			if !ok {
				continue
			}
			sort.SliceStable(items, func(i, j int) bool {
				left, _ := json.Marshal(items[i])
				right, _ := json.Marshal(items[j])
				return string(left) < string(right)
			})
		}
	case []any:
		for _, child := range value {
			normalizeSelectorOrder(child, section)
		}
	}
}

// isNodeAttrsSection reports whether section names the nodeAttrs block. The
// comparison folds case because merge never calls Load: it sees whatever
// spelling the fragment used, and Tailscale's legacy policy style capitalizes
// section names — the same reason resolveTopLevelKey exists. An exact match
// here would leave a legacy-spelled grants[].App payload ungated, sorting a
// member the capability owns and collapsing two distinct grants into one.
func isNodeAttrsSection(section string) bool {
	return strings.EqualFold(section, nodeAttrsKey)
}

// isUnorderedSelectorField reports whether key names a selector list whose
// order is not identity. The nodeAttrs names are section-scoped because they
// are ordinary English words a capability payload may also use.
func isUnorderedSelectorField(key, section string) bool {
	switch key {
	case policySourceField, policyDestinationField, "ip", policyUsersField, "srcPosture", "via":
		return true
	case "target", nodeAttrAttrKey, nodeAttrIPPoolKey, "connectors", "domains":
		return isNodeAttrsSection(section)
	default:
		return false
	}
}

func memberKey(member *hujson.ObjectMember) (string, error) {
	literal, ok := member.Name.Value.(hujson.Literal)
	if !ok {
		return "", fmt.Errorf("object key is not a literal: %s", member.Name.Pack())
	}
	var key string
	if err := json.Unmarshal([]byte(literal), &key); err != nil {
		return "", fmt.Errorf("decoding object key %q: %w", string(literal), err)
	}
	return key, nil
}

// ACLFilesInDirectories returns inputs in directory order and lexical order
// within each directory. Generic JSON or HuJSON files are ignored; inputs must
// identify themselves as ACL files by name.
func ACLFilesInDirectories(dirs []string, outputPath string) ([]string, error) {
	var absoluteOutput string
	if outputPath != "-" {
		var err error
		absoluteOutput, err = filepath.Abs(outputPath)
		if err != nil {
			return nil, fmt.Errorf("resolving output path %s: %w", outputPath, err)
		}
		absoluteOutput = filepath.Clean(absoluteOutput)
	}

	seen := make(map[string]bool)
	var paths []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("reading directory %s: %w", dir, err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if !entry.Type().IsRegular() || !IsACLFilename(entry.Name()) {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			absolute, absErr := filepath.Abs(path)
			if absErr != nil {
				return nil, fmt.Errorf("resolving input path %s: %w", path, absErr)
			}
			absolute = filepath.Clean(absolute)
			if absolute == absoluteOutput || seen[absolute] {
				continue
			}
			seen[absolute] = true
			paths = append(paths, path)
		}
	}
	return paths, nil
}

// IsACLFilename reports whether name is an eligible directory merge input.
func IsACLFilename(name string) bool {
	lower := strings.ToLower(name)
	extension := filepath.Ext(lower)
	if extension != ".json" && extension != ".hujson" {
		return false
	}
	base := strings.TrimSuffix(lower, extension)
	return base == "acl" || strings.HasSuffix(base, ".acl")
}
