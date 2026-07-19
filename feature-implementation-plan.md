# Feature Implementation Plan

Generated: 2026-07-19
Project: rvuln0-scan

## Summary

rvuln0-scan has 10 high-confidence feature gaps identified across 7 categories. The codebase is functional but lacks several features that comparable tools (Nuclei, httpx, rapiscm) provide.

## Ranked Feature Candidates

### 1. YAML-based custom checks [Impact: Critical, Effort: Medium, Confidence: High]

**Evidence**: All 20 checks are hardcoded in `src/check/builtin.rs`. The `Check` struct and `Matchers` system in `src/types.rs` already support external definition. No YAML parser is loaded.

**Description**: Add a `--check-file` flag to load user-defined vulnerability checks from YAML files. This is the primary differentiator between a hardcoded scanner and an extensible one. Makes rvuln0-scan community-contributable.

**Implementation sketch**:
1. Add `serde_yaml` dependency
2. Create `src/check/loader.rs` — parse YAML file into Vec<Check>
3. Add `--check-file` / `-c` flag to `check` and `scan` subcommands
4. Merge loaded checks with built-in checks before running

**Files likely affected**: `Cargo.toml`, `src/check/mod.rs`, `src/check/loader.rs` (new), `src/cli.rs`, `src/types.rs`

---

### 2. HTML report output [Impact: High, Effort: Small, Confidence: High]

**Evidence**: No `format_findings` handler for HTML in `src/report/mod.rs`. The rapiscm sibling project has `site.rs` for static HTML reports.

**Description**: Add `--format html` that generates a standalone HTML report with findings table, severity badges, and summary stats. Useful for CI artifacts and sharing results.

**Implementation sketch**:
1. Create `src/report/html.rs` with HTML template
2. Wire into `format_findings()`
3. Add HTML formatting to format string list in CLI help

**Files likely affected**: `src/report/html.rs` (new), `src/report/mod.rs`, `src/cli.rs`

---

### 3. Observability / structured logging [Impact: High, Effort: Small, Confidence: High]

**Evidence**: Zero logging infrastructure. `scan` subcommand silently discards errors from failed probes (`Err(_) => (target, vec![])`). No way to see which targets failed.

**Description**: Add a `--verbose` flag and structured logging via `tracing` or `log` crate. Show probe progress, errors, and scan summary. Critical for debugging batch scans.

**Implementation sketch**:
1. Add `log` or `tracing` crate
2. Replace `eprintln!` with structured logging
3. Add `--verbose` / `-v` flag to all subcommands
4. Log errors in `cmd_scan` instead of discarding them

**Files likely affected**: `Cargo.toml`, `src/main.rs`, `src/cli.rs`, `src/probe/http.rs`

---

### 4. Fuzzing engine [Impact: High, Effort: Large, Confidence: Medium]

**Evidence**: No `src/fuzz/` directory exists despite being in the original plan. The CLI has no `fuzz` subcommand.

**Description**: Add path fuzzing (`rvuln0 fuzz <target>` with wordlist) to discover hidden endpoints, parameters, and files. Common wordlists included.

**Implementation sketch**:
1. Create `src/fuzz/mod.rs` with `FuzzRunner`
2. Add `fuzz` subcommand to CLI
3. Include built-in wordlist (~200 common API paths)
4. Add `--wordlist`, `--extensions` flags

**Files likely affected**: `src/fuzz/mod.rs` (new), `src/cli.rs`, `src/main.rs`

---

### 5. Rate limiting in scan mode [Impact: Medium, Effort: Small, Confidence: High]

**Evidence**: The `--rate-limit` flag is defined in CLI but unused in `cmd_scan`. The `scan` command passes all targets concurrently with no rate limiting.

**Description**: Wire the `--rate-limit` flag into the scan loop. Use a token-bucket or `tokio::sync::Semaphore` with per-second allowance.

**Implementation sketch**:
1. Add rate limiter to `cmd_scan` loop
2. Use tokio::time::sleep between permits

**Files likely affected**: `src/main.rs`

---

### 6. Configuration file support [Impact: Medium, Effort: Small, Confidence: Medium]

**Evidence**: `src/config.rs` has a `build_config()` function that builds `ScanConfig` but is never called. All config is passed via CLI flags.

**Description**: Add `--config` flag to load defaults from a YAML/TOML file. Store persistent settings (default headers, proxy, ghost mode).

**Implementation sketch**:
1. Wire `build_config()` into the command dispatch
2. Add `--config` flag to root CLI
3. Load config file before CLI arg parsing, merge with CLI overrides

**Files likely affected**: `src/config.rs`, `src/cli.rs`, `src/main.rs`

---

### 7. Probe path enumeration [Impact: Medium, Effort: Medium, Confidence: High]

**Evidence**: The `probe` subcommand only probes a single URL. httpx supports probing multiple paths per host. No path enumeration exists.

**Description**: Add `--paths` flag to `probe` and `check` subcommands. Probe multiple common paths and report findings per path.

**Implementation sketch**:
1. Add `--paths` flag accepting comma-separated paths
2. In `cmd_probe`, iterate over paths
3. Return combined findings

**Files likely affected**: `src/cli.rs`, `src/main.rs`

---

### 8. Concurrent target scanning with progress [Impact: Medium, Effort: Small, Confidence: High]

**Evidence**: `cmd_scan` spawns all tasks at once with semaphore but shows no progress. For large target lists, the user sees no feedback.

**Description**: Show progress counter (e.g., `[12/50] Checking...`) during scan. Print a summary line at the end.

**Implementation sketch**:
1. Add atomic counter for completed scans
2. Print progress every N completions

**Files likely affected**: `src/main.rs`

---

### 9. JSON output for probe command [Impact: Low, Effort: Small, Confidence: High]

**Evidence**: `probe` command prints to terminal only. No `--format json` support. Users who want machine-readable probe output must parse terminal text.

**Description**: Add `--json` flag to probe command for JSON-formatted output.

**Implementation sketch**:
1. Add `--json` flag to Probe subcommand
2. Serialize ProbeResult to JSON when flag is set

**Files likely affected**: `src/cli.rs`, `src/main.rs`

---

### 10. Docker image [Impact: Low, Effort: Small, Confidence: High]

**Evidence**: No `Dockerfile` exists. CI workflow runs on ubuntu-latest but doesn't build a container image.

**Description**: Add a multi-stage Dockerfile for containerized scanning. Useful for CI/CD integration.

**Implementation sketch**:
1. Create `Dockerfile` with cargo-chef or multi-stage build
2. Add `.dockerignore`
3. Publish image to GHCR

**Files likely affected**: `Dockerfile`, `.dockerignore`, `.github/workflows/ci.yml`

---

## Phase 5: Summary

Found 10 feature gaps.

Top 5 by impact:
1. **YAML custom checks** (Critical, ~Medium)
2. **HTML report** (High, ~Small)
3. **Structured logging** (High, ~Small)
4. **Fuzzing engine** (High, ~Large)
5. **Rate limiting** (Medium, ~Small)

Full plan above.
