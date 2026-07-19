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
    let min = min_severity;
    let mut findings = Vec::new();

    // Matcher-based checks
    for check in check::builtin::all_checks() {
        if let Some(m) = min {
            if check.severity.rank() < m.rank() {
                continue;
            }
        }
        if check::matcher::matches(&check, probe) {
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

    // TLS checks
    if let Some(ref tls) = probe.tls {
        if tls.self_signed && min.is_none_or(|m| Severity::Medium.rank() >= m.rank()) {
            findings.push(Finding {
                target: probe.target.clone(),
                check_id: "tls-self-signed".into(),
                check_name: "Self-Signed Certificate".into(),
                severity: Severity::Medium,
                description: "The server uses a self-signed TLS certificate.".into(),
                detail: format!("Subject: {:?}", tls.subject),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }

        if let Some(ref not_after_str) = tls.not_after {
            if min.is_none_or(|m| Severity::High.rank() >= m.rank()) {
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc2822(not_after_str) {
                    let expiry_utc = expiry.with_timezone(&chrono::Utc);
                    let days_left = (expiry_utc - chrono::Utc::now()).num_days();
                    if days_left < 0 {
                        findings.push(Finding {
                            target: probe.target.clone(),
                            check_id: "tls-expired".into(),
                            check_name: "Expired Certificate".into(),
                            severity: Severity::High,
                            description: "The TLS certificate has expired.".into(),
                            detail: format!("Expired on: {not_after_str}"),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
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
