package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rshade/ax-go"
	"github.com/spf13/cobra"

	"github.com/rshade/tsacl/internal/aclpolicy"
	"github.com/rshade/tsacl/pkg/policycore/sanitize"
)

// commandDeps carries what every subcommand constructor needs. result is a
// pointer to run's result slot: a command body assigns through it so run can
// render the envelope after Execute returns, whatever the command was.
type commandDeps struct {
	opts       *options
	result     **result
	httpClient *http.Client
	apiURL     string
	format     *string
	colorRaw   *string
	getenv     func(string) string
	verbose    *bool
	sanitizer  **sanitize.Sanitizer
	axLogger   ax.Logger
}

func (d *commandDeps) logger() *slog.Logger { return newLoggerOn(d.axLogger, *d.verbose, *d.sanitizer) }

// colorize resolves whether human output on stdout should carry ANSI color.
// It reads the flag pointers after cobra has parsed them, so watch mode (which
// builds its streamEmitter inside a command's RunE) sees the resolved values.
func (d *commandDeps) colorize(w io.Writer) bool {
	mode, _ := parseColorMode(*d.colorRaw)
	return colorEnabled(*d.format, mode, w, d.getenv)
}

// addSubcommands registers the leaf commands, grouping related authoring
// commands under their noun parent.
func addSubcommands(root *cobra.Command, deps *commandDeps) {
	grant := &cobra.Command{Use: cmdGrant, Short: "Manage grants", RunE: runParentCommand}
	grant.AddCommand(newGrantAddCommand(deps), newGrantRemoveCommand(deps))

	group := &cobra.Command{Use: cmdGroup, Short: "Manage group definitions", RunE: runParentCommand}
	group.AddCommand(
		newDefinitionAddCommand(deps, aclpolicy.DefinitionGroup),
		newDefinitionRemoveCommand(deps, aclpolicy.DefinitionGroup),
	)

	ipset := &cobra.Command{Use: cmdIPSet, Short: "Manage ipset definitions", RunE: runParentCommand}
	ipset.AddCommand(
		newDefinitionAddCommand(deps, aclpolicy.DefinitionIPSet),
		newDefinitionRemoveCommand(deps, aclpolicy.DefinitionIPSet),
	)

	ssh := &cobra.Command{Use: cmdSSH, Short: "Manage SSH rules", RunE: runParentCommand}
	ssh.AddCommand(newSSHAddCommand(deps), newSSHRemoveCommand(deps))

	nodeAttr := &cobra.Command{Use: cmdNodeAttr, Short: "Manage node attributes", RunE: runParentCommand}
	nodeAttr.AddCommand(newNodeAttrAddCommand(deps), newNodeAttrRemoveCommand(deps))

	tagOwner := &cobra.Command{Use: cmdTagOwner, Short: "Manage tag owners", RunE: runParentCommand}
	tagOwner.AddCommand(newTagOwnerAddCommand(deps))

	host := &cobra.Command{Use: cmdHost, Short: "Manage host aliases", RunE: runParentCommand}
	host.AddCommand(newHostSetCommand(deps))

	posture := &cobra.Command{Use: cmdPosture, Short: "Manage posture definitions", RunE: runParentCommand}
	posture.AddCommand(newPostureSetCommand(deps), newPostureRemoveCommand(deps))

	autoApprover := &cobra.Command{
		Use:   cmdAutoApprover,
		Short: "Manage route and exit-node auto-approvers",
		RunE:  runParentCommand,
	}
	autoApprover.AddCommand(newAutoApproverAddCommand(deps), newAutoApproverRemoveCommand(deps))

	externalTailnet := &cobra.Command{
		Use:   cmdExternalTailnet,
		Short: "Manage externalTailnets aliases",
		RunE:  runParentCommand,
	}
	externalTailnet.AddCommand(
		newExternalTailnetAddCommand(deps),
		newExternalTailnetRemoveCommand(deps),
		newExternalTailnetListCommand(deps),
	)

	root.AddCommand(
		grant, group, ipset, ssh, nodeAttr, tagOwner, host, posture, autoApprover, externalTailnet,
		newInitCommand(deps),
		newMergeCommand(deps),
		newNormalizeCommand(deps),
		newValidateCommand(deps),
		newTestCommand(deps),
		newCheckCommand(deps),
		newLintCommand(deps),
		newJQCommand(deps),
		newPullCommand(deps),
		newPlanCommand(deps),
		newUploadCommand(deps),
	)
	wrapMutations(root, deps)
	declareNonDeterministic(root)
}
func newNodeAttrAddCommand(deps *commandDeps) *cobra.Command {
	var flags nodeAttrFlags
	cmd := &cobra.Command{
		Use:   subAdd,
		Short: "Add attributes or IP pools to a target set; target order is ignored and matching entries are merged",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := runNodeAttrAdd(deps.opts.file, flags.spec(), flags.comment,
				cmd.Flags().Changed(commentFlagName), flags.overwriteComment)
			*deps.result = out
			return err
		},
	}
	registerNodeAttrFlags(cmd, &flags, true)
	return cmd
}

func newNodeAttrRemoveCommand(deps *commandDeps) *cobra.Command {
	var flags nodeAttrFlags
	var index int
	cmd := &cobra.Command{
		Use:   subRemove,
		Short: "Remove node attributes or IP pools by target set, or one entry by --index",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Flags().Changed("index") {
				if flags.changed(cmd) {
					return usagef("nodeattr remove --index cannot be combined with node attribute fields")
				}
				out, err := runNodeAttrRemoveAt(deps.opts.file, index)
				*deps.result = out
				return err
			}
			out, err := runNodeAttrRemove(deps.opts.file, flags.spec())
			*deps.result = out
			return err
		},
	}
	registerNodeAttrFlags(cmd, &flags, false)
	cmd.Flags().IntVar(&index, "index", -1, "remove the nodeAttrs entry at this zero-based index")
	return cmd
}

type nodeAttrFlags struct {
	target, attr, ipPool stringListFlag
	comment              string
	overwriteComment     bool
}

func registerNodeAttrFlags(cmd *cobra.Command, flags *nodeAttrFlags, add bool) {
	cmd.Flags().Var(&flags.target, "target", "target selector; may be repeated")
	cmd.Flags().Var(&flags.attr, "attr", "node attribute name; may be repeated")
	cmd.Flags().Var(&flags.ipPool, "ip-pool", "IP pool CIDR; may be repeated")
	if add {
		registerCommentFlags(cmd.Flags(), &flags.comment, &flags.overwriteComment)
	}
}

func (f *nodeAttrFlags) spec() aclpolicy.NodeAttrSpec {
	return aclpolicy.NodeAttrSpec{
		Target: []string(f.target), Attr: []string(f.attr), IPPool: []string(f.ipPool),
	}
}

func (f *nodeAttrFlags) changed(cmd *cobra.Command) bool {
	return slices.ContainsFunc([]string{"target", "attr", "ip-pool"}, cmd.Flags().Changed)
}

func newSSHAddCommand(deps *commandDeps) *cobra.Command {
	var spec sshRuleFlags
	cmd := &cobra.Command{
		Use:   subAdd,
		Short: "Add an SSH rule; selector order is ignored, duplicate rules are a no-op, and check without a period differs from check with one",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := runSSHAdd(deps.opts.file, spec.spec(), spec.comment,
				cmd.Flags().Changed(commentFlagName), spec.overwriteComment)
			*deps.result = out
			return err
		},
	}
	registerSSHRuleFlags(cmd, &spec, true)
	return cmd
}

func newSSHRemoveCommand(deps *commandDeps) *cobra.Command {
	var spec sshRuleFlags
	var index int
	cmd := &cobra.Command{
		Use:   subRemove,
		Short: "Remove an SSH rule by semantic identity or --index",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Flags().Changed("index") {
				if spec.changed(cmd) {
					return usagef("ssh remove --index cannot be combined with SSH rule fields")
				}
				out, err := runSSHRemoveAt(deps.opts.file, index)
				*deps.result = out
				return err
			}
			out, err := runSSHRemove(deps.opts.file, spec.spec())
			*deps.result = out
			return err
		},
	}
	registerSSHRuleFlags(cmd, &spec, false)
	cmd.Flags().IntVar(&index, "index", -1, "remove the SSH rule at this zero-based index")
	return cmd
}

type sshRuleFlags struct {
	action, checkPeriod                  string
	source, destination, users, recorder stringListFlag
	enforceRecorder                      bool
	comment                              string
	overwriteComment                     bool
}

func registerSSHRuleFlags(cmd *cobra.Command, flags *sshRuleFlags, add bool) {
	cmd.Flags().StringVar(&flags.action, "action", "", "SSH action: accept or check")
	cmd.Flags().Var(&flags.source, "src", "source selector; may be repeated")
	cmd.Flags().Var(&flags.destination, "dst", "destination node selector; may be repeated")
	cmd.Flags().Var(&flags.users, "user", "SSH login name or autogroup; may be repeated")
	cmd.Flags().Var(&flags.users, "users", "alias for --user; may be repeated")
	cmd.Flags().Var(&flags.recorder, "recorder", "recorder node selector; may be repeated")
	cmd.Flags().StringVar(&flags.checkPeriod, "check-period", "",
		"for action check, re-authorize after a positive DURATION or always; omitted means no period and differs from an explicit period")
	cmd.Flags().BoolVar(&flags.enforceRecorder, "enforce-recorder", false, "require the recorder for this rule")
	if add {
		registerCommentFlags(cmd.Flags(), &flags.comment, &flags.overwriteComment)
	}
}

func (f *sshRuleFlags) spec() aclpolicy.SSHRuleSpec {
	return aclpolicy.SSHRuleSpec{
		Action: f.action, Source: []string(f.source), Destination: []string(f.destination),
		Users: []string(f.users), CheckPeriod: f.checkPeriod, CheckPeriodSet: f.checkPeriod != "",
		Recorder: []string(f.recorder), EnforceRecorder: f.enforceRecorder,
	}
}

func (f *sshRuleFlags) changed(cmd *cobra.Command) bool {
	return slices.ContainsFunc(
		[]string{"action", "src", "dst", "user", "users", "recorder", "check-period", "enforce-recorder"},
		cmd.Flags().Changed,
	)
}

func newDefinitionAddCommand(deps *commandDeps, kind aclpolicy.DefinitionKind) *cobra.Command {
	if kind == aclpolicy.DefinitionIPSet {
		return newIPSetAddCommand(deps)
	}
	var name, comment string
	var members stringListFlag
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subAdd,
		Short: "Add members to a " + string(kind) + " definition",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := runDefinitionAdd(
				deps.opts.file, kind, name, []string(members), comment,
				cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&name, "name", "", string(kind)+" definition name ("+string(kind)+":NAME)")
	cmd.Flags().Var(&members, "member", "group login or autogroup; may be repeated")
	registerCommentFlags(cmd.Flags(), &comment, &overwriteComment)
	return cmd
}

// newIPSetAddCommand registers --member and --cidr on one ordered member
// list: an ipset with operations is an ordered program, so the two flags
// must keep their interleaving rather than collecting into two lists.
func newIPSetAddCommand(deps *commandDeps) *cobra.Command {
	var name, comment string
	var members []aclpolicy.IPSetMemberSpec
	var overwriteComment bool
	kind := aclpolicy.DefinitionIPSet
	cmd := &cobra.Command{
		Use:   subAdd,
		Short: "Add members to an ipset definition",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := runIPSetAdd(
				deps.opts.file, name, members, comment,
				cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&name, "name", "", string(kind)+" definition name ("+string(kind)+":NAME)")
	cmd.Flags().Var(&ipsetMemberFlag{members: &members}, "member",
		"CIDR, address, range A-B, host:ALIAS, ipset:NAME, or add|remove MEMBER; may be repeated")
	cmd.Flags().Var(&ipsetMemberFlag{members: &members, cidrOnly: true}, "cidr",
		"CIDR prefix; a --member restricted to that form; may be repeated")
	registerCommentFlags(cmd.Flags(), &comment, &overwriteComment)
	return cmd
}

// ipsetMemberFlag appends to a member list shared between --member and
// --cidr, tagging each value with the flag it came from so --cidr keeps its
// CIDR-only validation.
type ipsetMemberFlag struct {
	members  *[]aclpolicy.IPSetMemberSpec
	cidrOnly bool
}

func (f *ipsetMemberFlag) Set(value string) error {
	if value == "" {
		return errors.New("value cannot be empty")
	}
	*f.members = append(*f.members, aclpolicy.IPSetMemberSpec{Value: value, CIDROnly: f.cidrOnly})
	return nil
}

func (f *ipsetMemberFlag) String() string {
	var values []string
	for _, member := range *f.members {
		if member.CIDROnly == f.cidrOnly {
			values = append(values, member.Value)
		}
	}
	return strings.Join(values, ",")
}

// Type satisfies pflag.Value. The name appears in --help as the flag's
// argument placeholder.
func (f *ipsetMemberFlag) Type() string { return "stringList" }

func newDefinitionRemoveCommand(deps *commandDeps, kind aclpolicy.DefinitionKind) *cobra.Command {
	var name string
	var force bool
	cmd := &cobra.Command{
		Use:   subRemove,
		Short: "Remove a " + string(kind) + " definition",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runDefinitionRemove(deps.opts.file, kind, name, force)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&name, "name", "", string(kind)+" definition name ("+string(kind)+":NAME)")
	cmd.Flags().BoolVar(&force, "force", false,
		"remove even when policy rules still reference the definition")
	return cmd
}

func newNormalizeCommand(deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   cmdNormalize,
		Short: "Emit the policy as standard JSON for general-purpose JSON tools",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runNormalize(deps.opts.file)
			*deps.result = out
			return err
		},
	}
}

// splitCommaList flattens a repeatable stringListFlag into a single list,
// splitting each value on commas and dropping empties, so --scim-domains accepts
// both "--scim-domains a.com,b.com" and repeated "--scim-domains a.com
// --scim-domains b.com".
func splitCommaList(values stringListFlag) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		for part := range strings.SplitSeq(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

func newInitCommand(deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   cmdInit,
		Short: "Initialize an empty policy for typed authoring",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runInit(deps.opts.file)
			*deps.result = out
			return err
		},
	}
}

// runParentCommand is RunE for every noun parent registered by addSubcommands
// (TestParentCommandsDistinguishBareFromUnknownSubcommand enumerates them, so
// the set is asserted rather than restated here). Without an explicit RunE,
// cobra treats a command with only
// subcommands as non-runnable and returns [flag.ErrHelp] before ValidateArgs or
// PersistentPreRunE ever run — for *any* leftover args, not just none — so
// "tsacl grant bogus" printed help and exited 0 exactly like a bare
// "tsacl grant". Splitting the two here restores the documented exit-code
// scheme (2 = usage error) for a real mistake while keeping the bare case at
// exit 0: printing help and exiting 0 for a bare parent is what git remote,
// gh repo, and docker network all do, and is more useful than an error for a
// caller who is legitimately exploring the command tree.
// A bare parent prints the same page its own --help does, rather than a
// second hand-written rendering of the same facts.
func runParentCommand(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		commandHelp(cmd)
		return nil
	}
	return usagef("unknown %s command %q", cmd.Name(), args[0])
}

func newGrantAddCommand(deps *commandDeps) *cobra.Command {
	var source, destination, ip, srcPosture stringListFlag
	var comment string
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subAdd,
		Short: "Append a grant to the policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := runGrantAdd(
				deps.opts.file,
				[]string(source), []string(destination), []string(ip), []string(srcPosture),
				comment, cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().Var(&source, "src", "grant source; may be repeated")
	cmd.Flags().Var(&destination, "dst", "grant destination; may be repeated")
	cmd.Flags().Var(&ip, "ip", "IP protocol and port expression; may be repeated")
	cmd.Flags().Var(&srcPosture, "src-posture", "required device posture (posture:NAME); may be repeated")
	cmd.Flags().StringVar(&comment, commentFlagName, "", "attach TEXT to the authored entry as a leading // comment")
	cmd.Flags().BoolVar(&overwriteComment, overwriteFlagName, false,
		"replace the entry's existing comments instead of appending to them")
	return cmd
}

func newGrantRemoveCommand(deps *commandDeps) *cobra.Command {
	var index int
	cmd := &cobra.Command{
		Use:   subRemove,
		Short: "Remove a grant by index",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runGrantRemove(deps.opts.file, index)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().IntVar(&index, "index", -1, "index of the grant to remove")
	return cmd
}

// newTagOwnerAddCommand parses --comment/--overwrite-comment with pflag like
// every other command; the tradeoff is that TAG or OWNER beginning with "-"
// needs a "--" terminator before it (POSIX Utility Syntax Guideline 10), and
// --comment must be supplied before that terminator. This replaced
// DisableFlagParsing plus a hand-rolled interspersed scanner: that scanner let
// --help reach RunE as a raw positional instead of triggering cobra's help
// path, and let an unrecognized flag such as a typo'd "--commnet" silently
// become a positional and get written into the policy. Root's TraverseChildren
// still parses --file and the other global flags before this command is
// reached.
func newTagOwnerAddCommand(deps *commandDeps) *cobra.Command {
	var comment string
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subAdd + " TAG OWNER",
		Short: "Add an owner to a tag",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := runTagOwnerAdd(
				deps.opts.file, args, comment, cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	registerCommentFlags(cmd.Flags(), &comment, &overwriteComment)
	return cmd
}

// newHostSetCommand: see newTagOwnerAddCommand for why an ADDRESS beginning
// with "-" needs a "--" terminator.
func newHostSetCommand(deps *commandDeps) *cobra.Command {
	var comment string
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subSet + " NAME ADDRESS",
		Short: "Set a host alias to an address",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := runHostSet(
				deps.opts.file, args, comment, cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	registerCommentFlags(cmd.Flags(), &comment, &overwriteComment)
	return cmd
}

// newPostureSetCommand: see newTagOwnerAddCommand for why an argument
// beginning with "-" needs a "--" terminator, and --comment must precede it.
func newPostureSetCommand(deps *commandDeps) *cobra.Command {
	var comment string
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subSet + " NAME EXPR [EXPR ...]",
		Short: "Add or replace a posture's expression list",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := runPostureSet(
				deps.opts.file, args, comment, cmd.Flags().Changed(commentFlagName), overwriteComment,
				cmd.ErrOrStderr(),
			)
			*deps.result = out
			return err
		},
	}
	registerCommentFlags(cmd.Flags(), &comment, &overwriteComment)
	return cmd
}

func newPostureRemoveCommand(deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   subRemove + " NAME",
		Short: "Remove a posture definition",
		RunE: func(_ *cobra.Command, args []string) error {
			out, err := runPostureRemove(deps.opts.file, args)
			*deps.result = out
			return err
		},
	}
}

// newAutoApproverAddCommand takes the section as flags rather than as
// positionals the way tag-owner add does because exitNode has no key: one
// positional grammar cannot name both "the 10.0.0.0/8 entry" and "the flat
// list" without a sentinel value.
func newAutoApproverAddCommand(deps *commandDeps) *cobra.Command {
	var route string
	var exitNode bool
	var approvers stringListFlag
	var comment string
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subAdd,
		Short: "Add auto-approvers for a route or the exit-node list",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := runAutoApproverAdd(
				deps.opts.file, route, exitNode, []string(approvers),
				comment, cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&route, "route", "", "CIDR whose approver list to edit (autoApprovers.routes)")
	cmd.Flags().BoolVar(&exitNode, "exit-node", false,
		"edit the exit-node approver list instead (autoApprovers.exitNode)")
	cmd.Flags().Var(&approvers, "approver",
		"approver selector (user, group, tag, or autogroup); may be repeated")
	registerCommentFlags(cmd.Flags(), &comment, &overwriteComment)
	return cmd
}

func newAutoApproverRemoveCommand(deps *commandDeps) *cobra.Command {
	var route string
	var exitNode bool
	var approvers stringListFlag
	cmd := &cobra.Command{
		Use:   subRemove,
		Short: "Remove auto-approvers, pruning an emptied route key",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runAutoApproverRemove(deps.opts.file, route, exitNode, []string(approvers))
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&route, "route", "", "CIDR whose approver list to edit (autoApprovers.routes)")
	cmd.Flags().BoolVar(&exitNode, "exit-node", false,
		"edit the exit-node approver list instead (autoApprovers.exitNode)")
	cmd.Flags().Var(&approvers, "approver",
		"approver selector (user, group, tag, or autogroup); may be repeated")
	return cmd
}

func newMergeCommand(deps *commandDeps) *cobra.Command {
	var dirs stringListFlag
	var base, add, outPath string
	cmd := &cobra.Command{
		Use:   cmdMerge,
		Short: mergeSummary,
		Long: mergeSummary + ".\n\n" +
			"--dir compiles every file named acl.json, acl.hujson, *.acl.json or *.acl.hujson in the\n" +
			"given directories into standard JSON (comments are stripped). --base and --add deep-merge\n" +
			"one snippet into a base policy, keeping the base's HuJSON comments and the comments on keys the\n" +
			"snippet adds.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request := mergeRequest{
				file: deps.opts.file, dirs: []string(dirs), base: base, add: add, out: outPath,
			}
			return ax.PerformWithAudit(cmd.Context(), cmd.CommandPath(),
				func(context.Context) error {
					out, err := rehearseMerge(request)
					*deps.result = out
					return err
				},
				func(context.Context) error {
					out, err := runMerge(request)
					*deps.result = out
					return err
				},
			)
		},
	}
	cmd.Flags().Var(&dirs, "dir", "directory containing ACL files; may be repeated")
	cmd.Flags().StringVar(&base, "base", "", "base policy for a comment-preserving pair merge; requires --add")
	cmd.Flags().StringVar(&add, "add", "", "snippet to deep-merge into --base; requires --base")
	cmd.Flags().StringVar(&outPath, "out", "",
		"output file; defaults to --file with --dir and to --base with --base/--add")
	return cmd
}

func newValidateCommand(deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   cmdValidate,
		Short: "Validate the policy via the Tailscale API",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			out, err := runValidate(ctx, *deps.opts, deps.httpClient, deps.apiURL, deps.logger())
			*deps.result = out
			return err
		},
	}
}

func newTestCommand(deps *commandDeps) *cobra.Command {
	var watch bool
	var validate bool
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   cmdTest,
		Short: testSummary,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if validate && !watch {
				return usagef("--validate applies only to --watch; use the validate command for a single server check")
			}
			if cmd.Flags().Changed("interval") && !watch {
				return usagef("--interval applies only to --watch; nothing polls without it")
			}
			if interval <= 0 {
				return usagef("--interval must be positive, got %s", interval)
			}
			out, err := runTest(
				ctx,
				*deps.opts,
				testOptions{watch: watch, validate: validate, interval: interval},
				deps.logger(),
				newStreamEmitter(
					cmd.OutOrStdout(),
					*deps.format,
					deps.colorize(cmd.OutOrStdout()),
					*deps.sanitizer,
					metaFor(cmd.Context(), *deps.format),
				),
				deps.httpClient,
				deps.apiURL,
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().BoolVar(&watch, "watch", false,
		"re-run the assertions whenever the policy file changes; never exits non-zero for a verdict")
	cmd.Flags().BoolVar(&validate, "validate", false,
		"with --watch, validate each stable snapshot using the read-only Tailscale API")
	cmd.Flags().DurationVar(&interval, "interval", defaultWatchInterval, "polling interval for --watch")
	cmd.AddCommand(newTestAddCommand(deps), newTestRemoveCommand(deps))
	return cmd
}

type testEditFunc func(file, source string, deny, accept, postureAttrs []string, stderr io.Writer) (*result, error)

func newTestAddCommand(deps *commandDeps) *cobra.Command {
	return newTestEditCommand(deps, subAdd,
		"Add deny or accept policy test assertions without evaluating them",
		"posture attribute KEY=VALUE for the test entry; may be repeated. Typed like check's --posture-attr",
		runTestAdd)
}

func newTestRemoveCommand(deps *commandDeps) *cobra.Command {
	return newTestEditCommand(deps, subRemove,
		"Remove deny or accept policy test assertions; may renumber later assertion IDs",
		"target only the entry whose srcPostureAttrs matches exactly; may be repeated",
		runTestRemove)
}

func newTestEditCommand(deps *commandDeps, use, short, postureUsage string, edit testEditFunc) *cobra.Command {
	var source string
	var deny, accept, postureAttrFlags stringListFlag
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := edit(
				deps.opts.file, source, []string(deny), []string(accept),
				[]string(postureAttrFlags), cmd.ErrOrStderr(),
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&source, "src", "", "assertion source")
	cmd.Flags().Var(&deny, "deny", "denied destination in DST:PORT form; may be repeated")
	cmd.Flags().Var(&accept, "accept", "accepted destination in DST:PORT form; may be repeated")
	cmd.Flags().Var(&postureAttrFlags, "src-posture-attr", postureUsage)
	return cmd
}

func newCheckCommand(deps *commandDeps) *cobra.Command {
	var source, destination, protocol string
	var port int
	var postureAttrFlags stringListFlag
	var postureAttrsComplete bool
	cmd := &cobra.Command{
		Use:   cmdCheck,
		Short: "Answer one reachability question locally",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			src, target, proto, err := resolveCheckTarget(
				source, destination, cmd.Flags().Changed("port"), port, protocol,
			)
			if err != nil {
				return err
			}
			postureAttrs, err := aclpolicy.ParsePostureAttrs([]string(postureAttrFlags))
			if err != nil {
				return usageError{err}
			}
			out, err := runCheck(
				ctx, *deps.opts, src, target, proto, postureAttrs, postureAttrsComplete, deps.logger(),
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&source, "src", "", "source user, group, tag, host, IP, or CIDR")
	cmd.Flags().StringVar(&destination, "dst", "", "destination selector, optionally with :port")
	cmd.Flags().IntVar(&port, "port", -1, "destination port (alternative to including it in --dst)")
	cmd.Flags().StringVar(&protocol, "proto", string(aclpolicy.ProtocolAny),
		"IP protocol to ask about: tcp|udp|sctp|any")
	cmd.Flags().Var(&postureAttrFlags, "posture-attr",
		"posture attribute KEY=VALUE; may be repeated. Values are typed: true/false are booleans, "+
			"JSON numbers are numbers, 'quoted' and \"quoted\" are strings, anything else is a bare string")
	cmd.Flags().BoolVar(&postureAttrsComplete, "posture-attrs-complete", false,
		"assert the --posture-attr set is complete: attributes it omits are unset")
	return cmd
}

func newLintCommand(deps *commandDeps) *cobra.Command {
	var severity, wildcard, configPath string
	var strictSCIMGroups bool
	var online bool
	var scimDomains stringListFlag
	cmd := &cobra.Command{
		Use:   cmdLint,
		Short: lintSummary,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			lintOpts, threshold, err := resolveLintOptions(
				severity, wildcard, strictSCIMGroups, scimDomains,
			)
			if err != nil {
				return err
			}
			out, err := runLint(
				ctx, *deps.opts, lintOpts, threshold, cmd.Flags().Changed("severity"), configPath,
				online, deps.httpClient, deps.apiURL, deps.logger(),
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&severity, "severity", string(aclpolicy.LintWarn),
		"lowest finding severity to report and fail on when set: advice|info|warn|error; "+
			"when omitted, report all and fail on warn or error")
	cmd.Flags().StringVar(&wildcard, "wildcard", string(aclpolicy.WildcardAnyToAny),
		"over-broad wildcard policy: any-to-any|any|off")
	cmd.Flags().StringVar(&configPath, "config", "",
		"HuJSON lint config path (currently broad-rule-untested allowBroad exclusions)")
	cmd.Flags().BoolVar(&strictSCIMGroups, "strict-scim-groups", false,
		"error on undeclared SCIM/IdP-synced groups (group:<name>@<domain>) instead of exempting them")
	cmd.Flags().Var(&scimDomains, "scim-domains",
		"narrow the SCIM-group exemption to these @domains and their subdomains "+
			"(comma-separated; may be repeated)")
	cmd.Flags().BoolVar(&online, "online-validation", false,
		"check svc: destinations and SCIM group sync against the control plane, read-only "+
			"(looks up each service, then submits the policy to /acl/validate); requires --tailnet and API-key or OAuth credentials")
	return cmd
}

func newPlanCommand(deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   cmdPlan,
		Short: "Diff the policy against the live tailnet (read-only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			out, err := runPlan(ctx, *deps.opts, deps.httpClient, deps.apiURL, deps.logger())
			*deps.result = out
			return err
		},
	}
}

func newPullCommand(deps *commandDeps) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   cmdPull,
		Short: "Bootstrap a local policy from the live tailnet",
		Long: "Bootstrap a local policy from the live tailnet. This is an adoption step, not a routine sync; " +
			"an existing --file is preserved unless --force is supplied.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			out, err := runPull(ctx, *deps.opts, force, deps.httpClient, deps.apiURL)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing --file (use only for an intentional refresh)")
	return cmd
}

func newUploadCommand(deps *commandDeps) *cobra.Command {
	var acceptRemoteChanges bool
	cmd := &cobra.Command{
		Use:   cmdUpload,
		Short: "Upload the policy to the tailnet",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			ifMatchExplicit := cmd.Flags().Changed("if-match")
			if !ax.DryRunFromContext(cmd.Context()) {
				subject := "upload " + deps.opts.file + " to tailnet " + deps.opts.tailnet
				if _, err := ax.Confirm(cmd.Context(), subject); err != nil {
					return err
				}
			}
			return ax.PerformWithAudit(cmd.Context(), cmd.CommandPath(),
				func(rehearseCtx context.Context) error {
					out, err := rehearseUpload(
						rehearseCtx, *deps.opts, ifMatchExplicit, acceptRemoteChanges, deps.httpClient, deps.apiURL,
					)
					*deps.result = out
					return err
				},
				func(context.Context) error {
					out, err := runUpload(
						ctx, *deps.opts, ifMatchExplicit, acceptRemoteChanges, deps.httpClient, deps.apiURL,
					)
					*deps.result = out
					return err
				},
			)
		},
	}
	cmd.Flags().BoolVar(&acceptRemoteChanges, "accept-remote-changes", false,
		"upload without If-Match, explicitly accepting remote changes not present in --file")
	return cmd
}
