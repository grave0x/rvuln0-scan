pub mod matcher;
pub mod builtin;

use crate::types::{Finding, ProbeResult, Severity};

/// Run all applicable checks against a probe result.
pub async fn run_checks(
    probe: &ProbeResult,
    min_severity: Option<Severity>,
) -> Vec<Finding> {
    let checks = builtin::all_checks();
    let mut findings = Vec::new();

    for check in &checks {
        if let Some(min) = min_severity {
            if check.severity.rank() < min.rank() {
                continue;
            }
        }

        if matcher::matches(check, probe) {
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
