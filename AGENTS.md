# rvuln0-scan

Rust vulnerability scanner. More at `../Personal/rapiscm` sibling crate.

## Quick start

```sh
cargo build
cargo test
cargo clippy        # zero warnings
cargo fmt           # format before diff
```

## Conventions

- CLI: `clap` derive macros
- HTTP: `reqwest` with configurable timeouts
- Errors: `thiserror`, propagate with context
- Async: `tokio`
- Minimize external deps — prefer std

## Module layout

```
src/
  main.rs           # tokio::main, dispatch
  cli.rs            # clap CLI def
  config.rs         # scan config
  types.rs          # core types
  error.rs          # error enum
  probe/            # HTTP + TLS + tech detection
  check/            # vuln checks + matchers
  report/           # output formatters
  ghost/            # evasion (UA, jitter)
  filter/           # severity filtering
```
