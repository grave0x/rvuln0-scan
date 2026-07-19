pub mod check;
pub mod cli;
pub mod config;
pub mod error;
pub mod filter;
pub mod ghost;
pub mod probe;
pub mod report;
pub mod types;

pub use error::Error;

/// Install the global TLS crypto provider.
/// Safe to call multiple times — will only install once.
pub fn init_tls() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
pub use types::{Finding, ProbeResult, Severity, TlsInfo};

/// Blocking wrapper for check::run_checks (used in tests).
pub fn run_checks_blocking(probe: &ProbeResult, min_severity: Option<Severity>) -> Vec<Finding> {
    let extra: Vec<types::Check> = Vec::new();

    // We use tokio::runtime::Runtime to call the async version.
    let fut = check::run_checks(probe, min_severity, &extra);
    tokio::runtime::Runtime::new().unwrap().block_on(fut)
}

/// Blocking tech detection for tests.
pub fn detect_tech_blocking(probe: &ProbeResult) -> Vec<String> {
    probe::tech::detect_tech(probe)
}

/// Blocking report formatter for tests.
pub fn format_findings_blocking(findings: &[Finding], format: &str) -> String {
    match format {
        "json" => report::json::format_json(findings),
        _ => report::table::format_table(findings),
    }
}
