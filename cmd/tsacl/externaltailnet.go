package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rshade/tsacl/internal/aclpolicy"
)

func newExternalTailnetAddCommand(deps *commandDeps) *cobra.Command {
	var externalID string
	var allowIncoming bool
	var allowRefs []string
	var comment string
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subAdd + " ALIAS",
		Short: "Add an externalTailnets alias; repeating the same arguments is a no-op",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := runExternalTailnetAdd(
				deps.opts.policyFiles(), deps.opts.file, args, externalID, allowIncoming, allowRefs,
				comment, cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&externalID, "external-id", "", "external tailnet ID")
	cmd.Flags().BoolVar(&allowIncoming, "allow-incoming", false, "set allowIncomingConnections on the alias")
	cmd.Flags().StringArrayVar(
		&allowRefs, "allow-external-references-to", nil,
		"local group: or tag: selector the other tailnet may reference; may be repeated",
	)
	registerCommentFlags(cmd.Flags(), &comment, &overwriteComment)
	return cmd
}

func newExternalTailnetRemoveCommand(deps *commandDeps) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   subRemove + " ALIAS",
		Short: "Remove an externalTailnets alias; a referenced alias requires --force",
		RunE: func(_ *cobra.Command, args []string) error {
			out, err := runExternalTailnetRemove(deps.opts.policyFiles(), deps.opts.file, args, force)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "remove the alias even when a selector still names it")
	return cmd
}

func newExternalTailnetListCommand(deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   subList,
		Short: "List externalTailnets aliases",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			out, err := runExternalTailnetList(deps.opts.policyFiles(), deps.opts.file)
			*deps.result = out
			return err
		},
	}
}

func runExternalTailnetAdd(
	files aclpolicy.Files,
	path string,
	args []string,
	externalID string,
	allowIncoming bool,
	allowRefs []string,
	comment string,
	commentSet, overwriteComment bool,
) (*result, error) {
	if len(args) != 1 {
		return nil, usagef("usage: tsacl external-tailnet add ALIAS --external-id ID")
	}
	comment, overwriteComment, err := commentFromFlags(commentSet, comment, overwriteComment)
	if err != nil {
		return nil, err
	}
	policy, err := loadForEdit(files, path)
	if err != nil {
		return nil, err
	}
	edit, err := aclpolicy.AddExternalTailnet(policy, aclpolicy.ExternalTailnetSpec{
		Alias:                     args[0],
		ExternalID:                externalID,
		AllowIncomingConnections:  allowIncoming,
		AllowExternalReferencesTo: allowRefs,
	})
	if err != nil {
		return nil, usageError{err}
	}
	operations := append([]aclpolicy.PatchOperation{}, edit.Operations...)
	if comment != "" {
		var commentOps []aclpolicy.PatchOperation
		if edit.Existed {
			commentOps, err = commentOperations(
				files, path, comment, overwriteComment, externalTailnetsSection, edit.Alias,
			)
		} else {
			commentOps = []aclpolicy.PatchOperation{
				commentPatch(comment, overwriteComment, externalTailnetsSection, edit.Alias),
			}
		}
		if err != nil {
			return nil, err
		}
		operations = append(operations, commentOps...)
	}
	status := statusNoChanges
	message := fmt.Sprintf("external tailnet %s already matches in %s", edit.Alias, path)
	if len(operations) != 0 {
		if err = files.WritePatch(path, operations...); err != nil {
			return nil, err
		}
		status = statusOK
		message = fmt.Sprintf("updated external tailnet %s in %s", edit.Alias, path)
	}
	res := newResult(commandExternalTailnetAdd, status, message)
	res.File = path
	res.Edited = []editedValue{editedAlias(edit.Alias)}
	return res, nil
}

func runExternalTailnetRemove(files aclpolicy.Files, path string, args []string, force bool) (*result, error) {
	if len(args) != 1 {
		return nil, usagef("usage: tsacl external-tailnet remove ALIAS")
	}
	policy, err := loadForEdit(files, path)
	if err != nil {
		return nil, err
	}
	edit, err := aclpolicy.RemoveExternalTailnet(policy, args[0], force)
	if err != nil {
		if _, referenced := errors.AsType[*aclpolicy.ExternalTailnetReferenceError](err); referenced {
			return nil, err
		}
		return nil, usageError{err}
	}
	status := statusNoChanges
	message := fmt.Sprintf("external tailnet %s not present in %s", edit.Alias, path)
	if edit.Changed() {
		if err = files.WritePatch(path, edit.Operations...); err != nil {
			return nil, err
		}
		status = statusOK
		message = fmt.Sprintf("removed external tailnet %s from %s", edit.Alias, path)
	}
	res := newResult(commandExternalTailnetRemove, status, message)
	res.File = path
	res.Edited = []editedValue{editedAlias(edit.Alias)}
	return res, nil
}

func runExternalTailnetList(files aclpolicy.Files, path string) (*result, error) {
	policy, err := loadForEdit(files, path)
	if err != nil {
		return nil, err
	}
	entries := aclpolicy.ListExternalTailnets(policy)
	res := newResult(commandExternalTailnetList, statusOK, formatExternalTailnetList(entries))
	res.File = path
	res.ExternalTailnets = &entries
	return res, nil
}

func formatExternalTailnetList(entries []aclpolicy.ExternalTailnetEntry) string {
	if len(entries) == 0 {
		return "no external tailnets"
	}
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		line := fmt.Sprintf(
			"%s externalID=%s allowIncomingConnections=%t",
			entry.Alias, entry.ExternalID, entry.AllowIncomingConnections,
		)
		if len(entry.AllowExternalReferencesTo) > 0 {
			line += " allowExternalReferencesTo=" + strings.Join(entry.AllowExternalReferencesTo, ",")
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

const externalTailnetsSection = "externalTailnets"
