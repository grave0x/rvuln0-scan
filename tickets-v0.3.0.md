# Feature Tickets — rvuln0-scan v0.3.0

Generated: 2026-07-19
Source: feature-discover + deep-research(novel approaches)
Count: 25 tickets

---

### 1. AI Prompt-Based Check Generation [Impact: Critical, Effort: Large, Confidence: Medium]
**Novel approach**: Nuclei v3.x AI template generation
**Description**: Add `rvuln0 generate` subcommand that accepts natural-language prompts ("find Log4Shell in this app") and auto-generates YAML checks using an LLM API. Lowers barrier to custom check creation.
**Implementation sketch**:
- Add `generate` subcommand with `--prompt` flag
- Integrate with OpenAI/Anthropic API for check generation
- Parse LLM output into Check struct format
- Output to file or pipe directly into `check --check-file`
**Files affected**: `src/cli.rs`, `src/check/generator.rs` (new), `Cargo.toml`

---

### 2. EPSS/KEV Enrichment for Findings [Impact: Critical, Effort: Medium, Confidence: High]
**Novel approach**: Grype EPSS+KEV scoring
**Description**: Enrich every finding with exploit probability (EPSS score), CISA KEV status, and composite risk score. Users see not just "CVE-2024-xxx found" but "90% chance of exploitation in next 30 days."
**Implementation sketch**:
- Add `--enrich` flag that queries EPSS API and KEV catalog
- Add `epss_score` field to Finding struct
- Color-code findings by EPSS probability in table output
- Add risk score calculation (CVSS × EPSS × KEV)
**Files affected**: `src/types.rs`, `src/check/enricher.rs` (new), `src/report/table.rs`, `src/cli.rs`

---

### 3. SBOM-First Scanning Pipeline [Impact: High, Effort: Medium, Confidence: High]
**Novel approach**: Trivy/Grype SBOM-first
**Description**: Accept CycloneDX or SPDX SBOM as input (`--sbom`), extract dependency list, match against CVE database without network access to target. Enables air-gapped scanning, offline vuln detection, CI pipeline reuse.
**Implementation sketch**:
- Add `--sbom` flag to `check` subcommand
- Parse CycloneDX JSON into dependency list
- Match deps against local CVE database or OSV API
- Output findings in standard format
**Files affected**: `src/cli.rs`, `src/check/sbom.rs` (new), `src/types.rs`, `Cargo.toml` (cyclonedx-bom)

---

### 4. LLM Vulnerability Probes [Impact: High, Effort: Large, Confidence: Medium]
**Novel approach**: Garak LLM scanner
**Description**: Add `rvuln0 llm` subcommand that probes LLM endpoints (OpenAI-compatible, vLLM, Triton) for prompt injection, jailbreaks, data leakage, and dangerous code generation. Treats the LLM as a remote service to fuzz.
**Implementation sketch**:
- Create `src/llm/mod.rs` module
- Add `llm` subcommand with `--model`, `--prompt` flags
- Implement probe suites: injection, jailbreak, leakage
- Score model responses for safety violations
**Files affected**: `src/cli.rs`, `src/llm/mod.rs` (new), `src/llm/probes.rs` (new), `src/main.rs`

---

### 5. Template Digital Signing [Impact: High, Effort: Medium, Confidence: High]
**Novel approach**: Nuclei template signing
**Description**: Sign YAML check files with ed25519 signatures. Verify signatures before execution. Prevents supply-chain attacks where a malicious check file is substituted. Ships with a public keyring for community checks.
**Implementation sketch**:
- Add `--sign` flag to create signature for a check file
- Add `--verify` flag that rejects unsigned checks
- Use ed25519-dalek for signing
- Ship default public key for community checks
**Files affected**: `Cargo.toml`, `src/check/loader.rs`, `src/check/sign.rs` (new), `src/cli.rs`

---

### 6. Stateful REST API Fuzzing [Impact: High, Effort: Large, Confidence: Medium]
**Novel approach**: Microsoft RESTler
**Description**: Add `rvuln0 restler` subcommand that consumes OpenAPI specs, infers producer-consumer dependencies between endpoints, and generates stateful call sequences. Finds deep bugs stateless fuzzers miss.
**Implementation sketch**:
- Parse OpenAPI v3 spec into endpoint dependency graph
- Generate call sequences that respect response → next-request data flow
- Execute sequences, collect crashes and 500 errors
- Output minimal reproducing sequences
**Files affected**: `src/fuzz/api/mod.rs` (new), `src/fuzz/api/parser.rs` (new), `src/cli.rs`

---

### 7. Honeypot Detection Engine [Impact: High, Effort: Small, Confidence: High]
**Novel approach**: Nuclei honeypot detection
**Description**: During scan, track how many distinct check IDs match a target. If match concentration exceeds threshold, flag as potential honeypot. Suppress or tag results accordingly. Reduces false positives from deceptive targets.
**Implementation sketch**:
- Add `--honeypot-detect` flag
- Track match counts per target in ScanConfig
- If threshold exceeded, tag findings as `honeypot`
- Optionally suppress honeypot findings
**Files affected**: `src/check/mod.rs`, `src/types.rs`, `src/cli.rs`, `src/filter/mod.rs`

---

### 8. Uncover Engine Integration [Impact: High, Effort: Medium, Confidence: High]
**Novel approach**: Nuclei Uncover
**Description**: Add `rvuln0 uncover` subcommand that queries Shodan, Censys, FOFA, and other search engines to discover targets, then feeds them directly into scan. Enables continuous external attack surface monitoring.
**Implementation sketch**:
- Add `uncover` subcommand with `--query`, `--engine` flags
- Implement API clients for Shodan, Censys, FOFA
- Pipe results into `scan` subcommand
- Output discovered targets + scan findings
**Files affected**: `src/cli.rs`, `src/discover/uncover.rs` (new), `src/discover/mod.rs` (new)

---

### 9. Garak-Style LLM Probe Suites [Impact: Medium, Effort: Large, Confidence: Medium]
**Novel approach**: NVIDIA Garak probes
**Description**: Integrate 6 LLM probe types: prompt injection (65+ encoding variants), DAN jailbreak, malware code gen, package hallucination, data leakage, toxicity. Score LLM response safety on 0-100 scale.
**Implementation sketch**:
- Add `--probe-type` flag to `llm` subcommand
- Implement probe library with encoding variants
- Score responses using classifier heuristics
- Output safety report card
**Files affected**: `src/llm/probes.rs`, `src/llm/scorer.rs` (new)

---

### 10. Risk-Based Severity Scoring [Impact: High, Effort: Small, Confidence: High]
**Novel approach**: Composite risk scoring
**Description**: Replace flat severity levels with numeric risk score (0-100) that combines: CVSS base score + EPSS exploit probability + KEV status + asset criticality + check confidence. Sort findings by actual risk, not severity label.
**Implementation sketch**:
- Add `risk_score` field to Finding
- Calculate score from available data
- Add `--sort risk` flag to sort output
- Color-code by risk band in table output
**Files affected**: `src/types.rs`, `src/check/enricher.rs`, `src/report/table.rs`

---

### 11. WebSocket Endpoint Discovery [Impact: Medium, Effort: Small, Confidence: High]
**Novel approach**: Protocol discovery
**Description**: Probe for WebSocket endpoints by checking for `Upgrade: websocket` headers, common WS paths (`/ws`, `/socket.io`, `/ws/v1`), and 426 response codes. Report findings in tech detection output.
**Implementation sketch**:
- Add WebSocket probe to tech detection
- Check headers for `Upgrade: websocket`
- Try common WS paths with upgrade request
- Report in tech output
**Files affected**: `src/probe/ws.rs` (new), `src/probe/mod.rs`, `src/probe/tech.rs`

---

### 12. Template Versioning & Distribution [Impact: Medium, Effort: Medium, Confidence: Medium]
**Novel approach**: Package management for checks
**Description**: Add `rvuln0 check pull <check-id>` to download individual checks from a community registry, and `rvuln0 check push` to publish. Version checks with semver. Enable community check sharing.
**Implementation sketch**:
- Add `check pull/push/list/search` subcommands
- Implement simple registry protocol (GitHub-based)
- Version checks in YAML metadata
- Dependency resolution for check chains
**Files affected**: `src/cli.rs`, `src/check/registry.rs` (new)

---

### 13. Coverage-Guided Fuzzing [Impact: Medium, Effort: Large, Confidence: Low]
**Novel approach**: AFL++-style fuzzing
**Description**: Integrate coverage-guided fuzzing for compiled API parsers. Instrument binary, run inputs through coverage tracking, mutate inputs that reach new code paths. Finds memory corruption and crashes.
**Implementation sketch**:
- Add `fuzz coverage` subcommand
- Integrate with cargo-fuzz or libfuzzer
- Collect coverage data from instrumented binary
- Mutate seed corpus toward new coverage
- Triage crashes
**Files affected**: `src/fuzz/coverage.rs` (new), `Cargo.toml`

---

### 14. Composite CVE Dashboard [Impact: Medium, Effort: Medium, Confidence: High]
**Novel approach**: Multi-source CVE intelligence
**Description**: When a CVE check matches, enrich with data from OSV.dev, NVD, GitHub Advisory DB, and exploit-db. Show fix version, patch link, known exploits, and suggested remediation in a single view.
**Implementation sketch**:
- Query OSV API for matched CVEs
- Enrich finding with fix versions, patch URLs
- Check exploit-db for public exploits
- Display in extended output mode
**Files affected**: `src/check/enricher.rs`, `src/report/table.rs`

---

### 15. Agentless Cloud Scanning [Impact: High, Effort: Large, Confidence: Medium]
**Novel approach**: Trivy cloud scanning
**Description**: Add `rvuln0 cloud` subcommand that scans AWS/Azure/GCP accounts via APIs. Checks S3 bucket policies, IAM roles, security group rules, and managed K8s configs — no agent installed on targets.
**Implementation sketch**:
- Add `cloud aws|azure|gcp` subcommands
- Use cloud SDKs to enumerate resources
- Apply cloud-specific checks (S3 public, IAM over-permissive)
- Output findings in standard format
**Files affected**: `src/cloud/mod.rs` (new), `src/cloud/aws.rs` (new), `src/cli.rs`, `Cargo.toml`

---

### 16. OpenVEX Filtering for False Positives [Impact: High, Effort: Small, Confidence: High]
**Novel approach**: Grype OpenVEX
**Description**: Import OpenVEX documents that declare vendor status for specific CVEs (`not_affected`, `fixed`, `under_investigation`). Suppress findings that match VEX statements — eliminating false positives at scale.
**Implementation sketch**:
- Add `--vex` flag to load VEX documents
- Parse OpenVEX JSON format
- Match CVE + package against VEX status
- Filter results based on VEX declarations
**Files affected**: `src/check/vex.rs` (new), `src/filter/mod.rs`, `src/cli.rs`

---

### 17. Multi-Report Diff Across Scans [Impact: Medium, Effort: Medium, Confidence: High]
**Novel approach**: Scan comparison
**Description**: Add `rvuln0 diff <scan-a.json> <scan-b.json>` to compare findings across two scans. Show new, fixed, and regressed findings. Essential for CI/CD regression testing and patch validation.
**Implementation sketch**:
- Add `diff` subcommand
- Load two JSON result files
- Compare findings by check_id + target
- Output diff report (new/fixed/regressed)
**Files affected**: `src/cli.rs`, `src/report/diff.rs` (new)

---

### 18. Format-Specific Fuzzing [Impact: Medium, Effort: Medium, Confidence: Medium]
**Novel approach**: Context-aware fuzzing
**Description**: When fuzzing, detect parameter context (JSON body, XML, form-encoded, multipart, query string) and generate context-appropriate payloads. JSON injection for JSON endpoints, XXE for XML endpoints, SQLi for query params.
**Implementation sketch**:
- Detect Content-Type from probe response
- Route payload generation by content type
- Add payload sets for each format
- Score responses for injection indicators
**Files affected**: `src/fuzz/format.rs` (new), `src/fuzz/mod.rs`

---

### 19. gRPC Probe Support [Impact: Medium, Effort: Large, Confidence: Low]
**Novel approach**: Protocol expansion
**Description**: Add gRPC service reflection probe. Enumerate gRPC services and methods via reflection API, invoke methods with fuzzed inputs, detect crashes and error disclosures. Expands beyond HTTP/TLS.
**Implementation sketch**:
- Add gRPC connection via tonic
- Implement reflection client for service discovery
- Invoke methods with fuzzed protobuf payloads
- Report findings
**Files affected**: `src/probe/grpc.rs` (new), `Cargo.toml`

---

### 20. Vulnerability Age Tracking [Impact: Medium, Effort: Small, Confidence: High]
**Novel approach**: Aging metrics
**Description**: Track when each CVE was published. Show "days since publication" in findings. Prioritize old-but-unpatched CVEs over recent ones. Add aging summary to scan reports.
**Implementation sketch**:
- Add `published_date` to CVE data
- Calculate age in days
- Color-code by age bands in output
- Add aging summary to HTML report
**Files affected**: `src/types.rs`, `src/check/enricher.rs`, `src/report/html.rs`

---

### 21. Deep Scan Mode [Impact: Medium, Effort: Medium, Confidence: High]
**Novel approach**: Recursive path discovery
**Description**: When a path-based check returns 200, recursively enumerate that path with a secondary wordlist. Discovers deeper hidden endpoints. Example: /admin returns 200 → fuzz /admin/* for hidden panels.
**Implementation sketch**:
- Add `--deep` flag to `check` subcommand
- Track discovered paths during scan
- Run secondary fuzz on discovered 200 paths
- Merge results into findings
**Files affected**: `src/check/mod.rs`, `src/fuzz/mod.rs`, `src/cli.rs`

---

### 22. SARIF Multi-Run Merge [Impact: Medium, Effort: Small, Confidence: High]
**Novel approach**: Report aggregation
**Description**: Add `rvuln0 merge` subcommand that merges multiple SARIF/JSON result files into a single SARIF output. Enables aggregate reporting across teams, time periods, or scan types.
**Implementation sketch**:
- Add `merge` subcommand
- Parse multiple SARIF/JSON inputs
- Deduplicate by check_id + target
- Output single merged SARIF
**Files affected**: `src/cli.rs`, `src/report/merge.rs` (new)

---

### 23. WebSocket Message Fuzzing [Impact: Low, Effort: Medium, Confidence: Medium]
**Novel approach**: WS protocol fuzzing
**Description**: When WebSocket endpoint is detected, open connection and send fuzzed messages. Detect error messages, crashes, unexpected close frames, and injection vulnerabilities in WS message handlers.
**Implementation sketch**:
- Add `fuzz ws` subcommand
- Connect to WS endpoint
- Send fuzzed message payloads
- Monitor for error disclosures
**Files affected**: `src/fuzz/ws.rs` (new), `src/cli.rs`

---

### 24. CI/CD Exit Code Configuration [Impact: Medium, Effort: Small, Confidence: High]
**Novel approach**: Pipeline-friendly exit codes
**Description**: Add `--fail-on` flag that controls exit code behavior: `--fail-on critical` exits 1 only if critical findings exist, `--fail-on any` exits 1 for any finding. Enables graduated CI/CD quality gates.
**Implementation sketch**:
- Add `--fail-on` flag to check/scan
- Map severity to exit code
- Exit 1 if any finding matches threshold
- Document in README
**Files affected**: `src/cli.rs`, `src/main.rs`

---

### 25. Community Check Marketplace [Impact: Medium, Effort: Large, Confidence: Low]
**Novel approach**: Nuclei templates ecosystem
**Description**: Create `rvuln0 check marketplace` that lists available community checks, shows rating/downloads, and installs with one command. Requires a Git-based registry with semver versioning and GPG signing.
**Implementation sketch**:
- Design registry format (YAML index in GitHub repo)
- Add `check marketplace list|search|install` commands
- Verify signatures on install
- Track installed checks in local index.json
**Files affected**: `src/cli.rs`, `src/check/marketplace.rs` (new), `src/check/registry.rs`
