package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	diff "github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	"github.com/rshade/ax-go"
	"github.com/spf13/cobra"

	"github.com/rshade/tsacl/internal/observedstate"
	"github.com/rshade/tsacl/internal/tailapi"
)

// mutationNouns are the parents whose add, remove, and set leaves edit the
// policy file.
func mutationNouns() []string {
	return []string{
		cmdGrant, cmdGroup, cmdIPSet, cmdSSH, cmdNodeAttr, cmdTagOwner, cmdHost,
		cmdPosture, cmdAutoApprover, cmdExternalTailnet, cmdTest,
	}
}

func isMutation(root, cmd *cobra.Command) bool {
	parent := cmd.Parent()
	switch {
	case parent == nil || !cmd.Runnable():
		return false
	case parent == root:
		return cmd.Name() == cmdInit || cmd.Name() == cmdPull || cmd.Name() == cmdPlan
	case parent.Parent() == root:
		return cmd.Name() != subList && slices.Contains(mutationNouns(), parent.Name())
	}
	return false
}

// wrapMutations routes every command that writes the policy or state file
// through ax.PerformWithAudit: a real run commits, a --dry-run rehearses.
func wrapMutations(root *cobra.Command, deps *commandDeps) {
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		if isMutation(root, cmd) {
			wrapMutation(cmd, deps)
		}
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(root)
}

func wrapMutation(cmd *cobra.Command, deps *commandDeps) {
	inner := cmd.RunE
	audit := cmd.Name() != cmdPlan
	cmd.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		if !audit {
			ctx = ax.WithAudit(ctx, false)
		}
		return ax.PerformWithAudit(ctx, c.CommandPath(),
			func(context.Context) error { return rehearseOnPrivateCopy(c, args, deps, inner) },
			func(context.Context) error { return inner(c, args) },
		)
	}
}

func rehearseOnPrivateCopy(
	cmd *cobra.Command,
	args []string,
	deps *commandDeps,
	inner func(*cobra.Command, []string) error,
) error {
	realPath := deps.opts.file
	dir, err := os.MkdirTemp("", "tsacl-dry-run-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	tempPath := filepath.Join(dir, filepath.Base(realPath))
	before, err := copyIfPresent(realPath, tempPath)
	if err != nil {
		return err
	}
	if _, err = copyIfPresent(
		filepath.Join(filepath.Dir(realPath), observedstate.FileName),
		filepath.Join(dir, observedstate.FileName),
	); err != nil {
		return err
	}

	deps.opts.file = tempPath
	runErr := inner(cmd, args)
	deps.opts.file = realPath

	after, readErr := readIfPresent(tempPath)
	if readErr != nil {
		return readErr
	}
	if res := *deps.result; res != nil {
		res.DryRun = true
		res.Message = strings.ReplaceAll(res.Message, tempPath, realPath)
		res.File = strings.ReplaceAll(res.File, tempPath, realPath)
		if res.Diff == "" && !bytes.Equal(before, after) {
			res.Diff = unifiedDiff(realPath, before, after)
		}
	}
	return rewritePath(runErr, tempPath, realPath)
}

func copyIfPresent(from, to string) ([]byte, error) {
	data, err := readIfPresent(from)
	if err != nil || data == nil {
		return nil, err
	}
	return data, os.WriteFile(to, data, 0o600)
}

func readIfPresent(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func unifiedDiff(path string, before, after []byte) string {
	edits := myers.ComputeEdits(span.URIFromPath(path), string(before), string(after))
	return fmt.Sprint(diff.ToUnified("current", path, string(before), edits))
}

// rewritePath restores the real path in an error raised against the private
// copy while keeping the original error in the chain for classification.
func rewritePath(err error, tempPath, realPath string) error {
	if err == nil || !strings.Contains(err.Error(), tempPath) {
		return err
	}
	return &sanitizedError{message: strings.ReplaceAll(err.Error(), tempPath, realPath), err: err}
}

// rehearseMerge runs a merge with a capturing writer and reports the diff
// between the current output file and the merged document.
func rehearseMerge(request mergeRequest) (*result, error) {
	var target string
	var merged []byte
	request.write = func(path string, data []byte) error {
		target, merged = path, data
		return nil
	}
	res, err := runMerge(request)
	if res == nil {
		return res, err
	}
	res.DryRun = true
	before, readErr := readIfPresent(target)
	if readErr != nil {
		return res, readErr
	}
	if !bytes.Equal(before, merged) {
		res.Diff = unifiedDiff(target, before, merged)
	}
	return res, err
}

// rehearseUpload checks everything an upload would, without sending it: the
// flag rules, the recorded or explicit ETag against the deployed policy, and
// the control plane's own validation of the candidate. It needs only the
// read-only scope.
func rehearseUpload(
	ctx context.Context,
	opts options,
	ifMatchExplicit, acceptRemoteChanges bool,
	httpClient *http.Client,
	apiURL string,
) (*result, error) {
	if err := checkUploadFlags(opts, ifMatchExplicit, acceptRemoteChanges); err != nil {
		return nil, err
	}
	client, err := apiClient(opts, httpClient, apiURL, tailapi.ScopePolicyFileRead)
	if err != nil {
		return nil, err
	}
	ifMatch, err := resolveUploadETag(opts, ifMatchExplicit, acceptRemoteChanges)
	if err != nil {
		return nil, err
	}
	plan, err := tailapi.PlanFile(ctx, client, opts.file)
	err = tailapi.WrapOAuthError(err, tailapi.ScopePolicyFileRead, opts.oauthClientID, opts.oauthClientSecret)
	if err != nil {
		return nil, err
	}
	if ifMatch != "" && strings.Trim(ifMatch, `"`) != strings.Trim(plan.ETag, `"`) {
		return nil, errors.New(staleUploadRemediation)
	}
	res := newResult(cmdUpload, statusOK,
		fmt.Sprintf("dry run: would upload %s to tailnet %s", opts.file, opts.tailnet))
	res.File = opts.file
	res.Tailnet = opts.tailnet
	res.Authentication = authenticationName(opts)
	res.ETag = plan.ETag
	res.DryRun = true
	changed := plan.Changed
	res.Changed = &changed
	if plan.Changed {
		res.Diff = plan.Diff
	}
	return res, nil
}
