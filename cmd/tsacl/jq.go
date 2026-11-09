package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/itchyny/gojq"
	"github.com/spf13/cobra"
	"github.com/tailscale/hujson"
)

func newJQCommand(deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   cmdJQ + " PROGRAM",
		Short: "Query the policy with the embedded jq engine",
		Long: "Standardize the HuJSON policy, evaluate PROGRAM with gojq, and report the " +
			"matched values. Human output is NDJSON, one JSON value per line; JSON output " +
			"carries the same values under the envelope's results key.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usagef("jq requires exactly one PROGRAM argument")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			buffered := *deps.format == formatJSON
			values, err := runJQ(ctx, deps.opts.file, args[0], buffered, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			if buffered {
				res := newResult(cmdJQ, statusOK,
					fmt.Sprintf("query returned %d value(s) from %s", len(values), deps.opts.file))
				res.File = deps.opts.file
				res.Results = &values
				*deps.result = res
			}
			return nil
		},
	}
}

// runJQ evaluates program against the standardized policy, returning the
// matched values when buffered and streaming them to stdout when not.
//
// The two formats consume the results differently enough to take different
// paths. Human output streams NDJSON as gojq yields each value, which is what
// keeps the command composable with line-oriented tools. JSON output cannot
// stream: convention 2's envelope has to carry the whole result set under one
// key, so the caller buffers and render emits it.
//
// The visible consequence is that a mid-stream evaluation error leaves the
// values produced before it on stdout in human mode, and nothing at all in
// JSON mode. Both are parse-clean — every human line is a complete JSON value
// — and the non-zero exit is what tells a consumer the run was truncated.
func runJQ(ctx context.Context, path, program string, buffered bool, stdout io.Writer) ([]any, error) {
	query, err := gojq.Parse(program)
	if err != nil {
		return nil, usagef("could not parse jq program: %v", err)
	}
	input, err := decodePolicyForQuery(path)
	if err != nil {
		return nil, err
	}

	values := []any{}
	encoder := json.NewEncoder(stdout)
	iterator := query.RunWithContext(ctx, input)
	for {
		value, ok := iterator.Next()
		if !ok {
			return values, nil
		}
		if queryErr, isError := value.(error); isError {
			return nil, usagef("jq evaluation failed: %v", queryErr)
		}
		if buffered {
			values = append(values, value)
			continue
		}
		if err = encoder.Encode(value); err != nil {
			return nil, fmt.Errorf("writing jq result: %w", err)
		}
	}
}

// decodePolicyForQuery standardizes the HuJSON policy and decodes it into the
// generic Go values gojq evaluates against.
//
// UseNumber is load-bearing: a bare decode lands every number in a float64 and
// silently rounds an integer past 2^53, which a policy carrying a device or
// user ID would hit. gojq normalizes [json.Number] itself, so preserving the
// literal here costs nothing downstream.
func decodePolicyForQuery(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, usagef("could not read policy %s: %v", path, err)
	}
	standard, err := hujson.Standardize(raw)
	if err != nil {
		return nil, usagef("could not parse policy %s: %v", path, err)
	}
	var input any
	decoder := json.NewDecoder(bytes.NewReader(standard))
	decoder.UseNumber()
	if err = decoder.Decode(&input); err != nil {
		return nil, usagef("could not decode policy %s: %v", path, err)
	}
	return input, nil
}
