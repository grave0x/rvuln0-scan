# rvuln0-scan

Rust vulnerability scanner. Inspired by sibling project `Personal/rapiscm` (Rust API scanner with 8 subcommands, 60+ flags, browser support).

## Status

Empty — new project. Plan + build from scratch.

## Quick start

```sh
cargo build
cargo test
cargo clippy        # must pass before commit
cargo fmt           # format before diff
```

## Conventions (inherit from rapiscm)

- CLI: `clap` derive macros
- HTTP: `reqwest` with configurable timeouts
- Errors: `anyhow` / `thiserror`, propagate with context
- Async: `tokio`
- Minimize external deps — prefer std (e.g. manual ANSI codes, `std::time`, `AtomicU64` IDs)

## Expected structure

```
src/
  main.rs           # tokio::main, dispatch
  cli.rs            # clap CLI def
  config.rs         # scan config
  types.rs          # core types
  error.rs          # error enum
  scan/             # scan logic
  check/            # vuln checks
  report/           # output formatters
  fuzz/             # optional fuzzing
```

## Reference

- `../Personal/rapiscm/` — sibling crate with similar patterns: module layout, CI workflow, feature-gated browser support
