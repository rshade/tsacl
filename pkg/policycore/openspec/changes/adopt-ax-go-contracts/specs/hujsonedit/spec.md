# Spec Delta

## ADDED Requirements

### Requirement: File reads are bounded

Every file read by `ParseFile`, `WritePatch`, `LeadingComments`, and the
bounded raw read SHALL accept a file of exactly the limit and SHALL reject
a larger file with code `config_too_large`, exit code 2, and the text
`<path>: config exceeds maximum size of <limit> bytes`. The default limit
SHALL be the exported `DefaultMaxBytes`, 16 MiB (16777216).

#### Scenario: The boundary

- **WHEN** `ParseFile` reads a valid document of exactly `DefaultMaxBytes`
  bytes, and then one of `DefaultMaxBytes+1` bytes
- **THEN** the first parses and the second fails with `config_too_large`
  before any parse

#### Scenario: An oversize file is never rewritten

- **WHEN** `WritePatch` is called on a file one byte over the limit
- **THEN** it fails with `config_too_large` and the file on disk is
  unchanged

### Requirement: The read limit is configurable up to ax-go's ceiling

A caller SHALL be able to set the limit for a read, `WritePatch` included,
to any value from 1 through ax-go's `config.MaxBytesCeiling`. A zero limit
SHALL mean the default. A negative limit, or one above the ceiling, SHALL
fail with code `config_max_bytes_invalid` and exit code 2 before the file
is opened.

#### Scenario: A raised limit accepts a larger file

- **WHEN** a 2 MiB document is read with the limit set to 4 MiB
- **THEN** it is read without error

#### Scenario: An out-of-range limit

- **WHEN** a read is attempted with the limit set to
  `MaxBytesCeiling + 1`
- **THEN** it fails with `config_max_bytes_invalid` and the file is not
  opened

### Requirement: A bounded raw read returns the bytes unparsed

The package SHALL provide a bounded read that returns a file's bytes under
the same limit, so a caller that decodes the document itself applies the
same limit as `ParseFile`.

#### Scenario: Raw bytes are returned verbatim

- **WHEN** the bounded raw read is called on a file under the limit
- **THEN** it returns exactly the file's bytes

### Requirement: Bytes the caller already holds parse with the same classification

The package SHALL parse a document the caller already holds, under a name
used only in the error text. A document that is not valid HuJSON SHALL fail
with `config_invalid` and the text `<name>: <hujson error>`, the same text
`ParseFile` produces for a file at that path.

#### Scenario: Parsing held bytes

- **WHEN** the bytes `{"grants": [,}` are parsed under the name
  `policy.hujson`
- **THEN** the error code is `config_invalid` and the text is
  `policy.hujson: hujson: line 1, column 13: invalid character ',' at start of value`

### Requirement: Parse, patch, and comment failures carry stable error codes

A document that is not valid HuJSON SHALL fail with `config_invalid`. A
patch operation, prune, or segment path that cannot apply to the document
SHALL fail with `config_patch_invalid`. Comment text that
`ValidateCommentText` rejects SHALL fail with `comment_invalid`. Each
SHALL keep its existing text, hujson's line and column included.

#### Scenario: Malformed HuJSON keeps its position detail

- **WHEN** `ParseFile` reads `{"grants": [,}`
- **THEN** the error code is `config_invalid` and the text is
  `<path>: hujson: line 1, column 13: invalid character ',' at start of value`

#### Scenario: A remove of an absent member

- **WHEN** `PatchBytes` applies `PatchRemove("groups", "group:absent")` to a
  document with no such member
- **THEN** the error code is `config_patch_invalid`

### Requirement: Error codes and exit codes match ax-go config

For the same oversize input, out-of-range limit, and malformed input,
`hujsonedit` SHALL return the same `error_code` and exit code as ax-go's
`config.Parse`.

#### Scenario: Parity on oversize and malformed input

- **WHEN** the same oversize and malformed documents are passed to
  `config.Parse` and to `ParseFile`
- **THEN** each pair reports the same `error_code` and the same exit code
