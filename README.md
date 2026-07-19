# rvuln0-scan

Rust vulnerability scanner for remote services and sites.

## Quick start

```sh
cargo build --release
cargo test
cargo clippy        # zero warnings expected
cargo fmt           # format before diff
```

## Usage

```sh
# Probe a URL — HTTP headers, tech detection, response info
rvuln0 probe https://example.com

# Run vulnerability checks
rvuln0 check https://example.com
rvuln0 check https://example.com --severity high --format json -o findings.json

# Batch scan targets from a file
rvuln0 scan -l targets.txt -o report.json --format json --threads 50
```

## Built-in checks

| ID | Severity | Description |
|----|----------|-------------|
| `missing-security-headers` | Medium | Missing X-Content-Type-Options / X-Frame-Options |
| `hsts-missing` | Low | Strict-Transport-Security not set |
| `csp-missing` | Low | Content-Security-Policy not set |
| `cors-wildcard` | Medium | CORS allows all origins (\*) |
| `server-banner` | Info | Server header leaks software version |
| `stack-trace` | High | Stack trace visible in response |
| `directory-listing` | Medium | Directory listing enabled |
| `exposed-admin` | High | Login/admin panel detected |
| `php-info-exposed` | High | phpinfo() output detected |

## Project layout

```
src/
  main.rs         # tokio::main, CLI dispatch
  cli.rs          # clap derive (probe, check, scan)
  types.rs        # core types
  error.rs        # error enum
  config.rs       # scan config builder
  probe/          # HTTP probing + tech detection + TLS
  check/          # vulnerability check engine + matchers
  ghost/          # evasion (UA rotation, jitter)
  report/         # output formatters (table, json, sarif)
  filter/         # severity filtering
```

## Flags

See `rvuln0 --help` for all subcommand flags.
