# ADR-003: CLI design — subcommands vs flag-driven

## Status

Accepted

## Date

2026-07-20

## Context

rvuln0-scan needs a CLI that is composable, discoverable, and works well in
pipelines (STDIN/STDOUT). The tool has three distinct use modes:
- Single URL probe (quick check)
- Single URL vulnerability check
- Batch scan from file

## Decision

Use **three subcommands** (`probe`, `check`, `scan`) with shared flags via
`clap` derive.

- `probe` — stateless HTTP probe. Returns headers, tech, TLS info. JSON output.
- `check` — probe + run vulnerability checks. Primary use case.
- `scan` — batch processing from file with concurrency control.

Shared flags (`--timeout`, `--proxy`, `-H`, `--ghost`, `-k`) are repeated
per subcommand for clarity (clap derive idiomatic approach).

## Alternatives Considered

### Single `scan` command with flags for everything
- Pros: Fewer subcommands to learn
- Cons: Flag combinatorics explode; `--list` + single URL flags conflict
- Rejected: Subcommands are more discoverable via `--help`

### Positional-only (like `nmap scanme.nmap.org`)
- Pros: Simple for common case
- Cons: Cannot distinguish "probe this URL" from "scan this URL"
- Rejected: Needs at least probe vs scan distinction

## Consequences

- Users start with `probe` to explore, graduate to `check` and `scan`
- Pipeline usage: `cat targets.txt | xargs -I{} rvuln0 check {} -f json`
- Each subcommand has its own `--help` with relevant flags only
- Some flag repetition across subcommands — acceptable trade-off
