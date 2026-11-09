# Auditable CLI conventions

This repository's command-line tools follow a shared contract designed for
both people and automation. The contract keeps results predictable, failures
visible, and machine output safe to consume.

## Output channels

Command results go to standard output. Diagnostics, progress messages, and
verbose logs go to standard error. A caller can therefore redirect or parse a
result without mixing it with operational commentary.

## Human and machine output

Human-readable output is the default. Tools that return structured results
also provide a JSON format with an explicit schema marker. Streaming commands
may use newline-delimited JSON so each record can be consumed independently.

Consumers should branch on documented fields rather than prose intended for a
person. Additive fields can appear within a schema version; removing, renaming,
or changing the meaning of an existing field requires a new version.

## Exit codes

The common exit-code vocabulary is:

| Code | Meaning |
| --- | --- |
| `0` | The command completed successfully and no failing verdict applies. |
| `1` | The command completed and produced a failing verdict. |
| `2` | The invocation, input, collection, or output operation failed. |
| `10` | The tool could not prove a definitive verdict, when supported. |

Each command documents its exact interpretation. In particular, warnings may
be non-fatal, report-writing modes may alter whether findings gate a process,
and not every tool needs an indeterminate state.

## Discoverability

Every binary provides rich command-line help, version information with build
provenance, and a machine-readable `-schema` surface plus the ax-go `__schema`
command. See the [agent runtime](agent-runtime.md) reference. Cobra-based tools also
provide shell completion.

Both single-dash long flags such as `-format` and conventional double-dash
forms such as `--format` are accepted for compatibility unless a command's
reference says otherwise.

## Collection and classification

Diagnostic and audit tools separate external collection from pure evaluation.
The same captured evidence and configuration should produce the same verdict.
Collection failures must remain visible; missing evidence must not silently
become a healthy result.

Read-only tools do not mutate the systems they inspect. Tools that intentionally
write state identify that boundary and provide safeguards such as validation,
planning, or optimistic concurrency.

## Safety and sensitive data

Credentials never belong in result output or flag defaults. Support captures
and audit reports can still contain sensitive inventory or network data, so
each tool documents its redaction and file-permission behavior.

## Source and build provenance

Published binaries report their version and embedded revision. Claims tied to
upstream data structures or behavior are pinned to source dependencies or
covered by fixtures where practical. Cross-platform tools are compiled for
Linux, Windows, and macOS in continuous integration.
