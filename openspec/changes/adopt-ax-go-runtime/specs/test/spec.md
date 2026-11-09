# Test Delta

## ADDED Requirements

### Requirement: Watch is refused under MCP

`test --watch` SHALL return a validation error when invoked through the MCP
server, instead of running a loop that never returns.

#### Scenario: Watch over MCP

- **WHEN** an MCP client calls `test` with `watch: true`
- **THEN** the call returns a validation error promptly
