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
pub use types::{Finding, ProbeResult, Severity, TlsInfo};

/// Blocking wrapper for check::run_checks (used in tests).
pub fn run_checks_blocking(probe: &ProbeResult, min_severity: Option<Severity>) -> Vec<Finding> {
    let checks = check::builtin::all_checks();
    let mut findings = Vec::new();

    for check in &checks {
        if let Some(min) = min_severity {
            if check.severity.rank() < min.rank() {
                continue;
            }
        }
        if check::matcher::matches(check, probe) {
            findings.push(Finding {
                target: probe.target.clone(),
                check_id: check.id.clone(),
                check_name: check.name.clone(),
                severity: check.severity,
                description: check.description.clone(),
                detail: format!("Matched on {} ({})", probe.url, probe.status_code),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }
    }
    findings
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
