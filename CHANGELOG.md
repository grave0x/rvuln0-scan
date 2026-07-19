# Changelog

## [0.1.0] - 2026-07-19

### Added
- Initial release of rvuln0-scan
- 4 subcommands: `probe`, `check`, `scan`, `fuzz`
- HTTP probing with connection pooling, redirects, proxy, ghost mode
- TLS certificate inspection (issuer, SANs, validity dates)
- 23 vulnerability checks (17 HTTP matcher-based + 3 TLS + custom YAML)
- 60+ technology fingerprints (servers, CDNs, CMS, frameworks, analytics)
- 4 report formats: table, JSON, SARIF, HTML
- YAML-based custom vulnerability checks (`--check-file`)
- Fuzzing engine with 92-path wordlist (`rvuln0 fuzz`)
- Concurrent scanning with rate limiting and progress display
- Environment logging with `--verbose` flag
- TOML config file support (`--config`)
- Multi-path probing (`--paths`)
- Docker multi-stage build (distroless runtime)
- GitHub Actions CI (check, fmt, clippy, test)
- 39 tests, zero clippy warnings
