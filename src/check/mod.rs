pub mod matcher;
pub mod builtin;

use crate::types::{Finding, ProbeResult, Severity};

/// Run all applicable checks against a probe result.
pub async fn run_checks(
    probe: &ProbeResult,
    min_severity: Option<Severity>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let min = min_severity;

    // Run matcher-based checks
    let checks = builtin::all_checks();
    for check in &checks {
        if let Some(m) = min {
            if check.severity.rank() < m.rank() {
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

    // Run TLS-specific checks
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
                    } else if days_left < 30 {
                        findings.push(Finding {
                            target: probe.target.clone(),
                            check_id: "tls-expiring-soon".into(),
                            check_name: "Certificate Expiring Soon".into(),
                            severity: Severity::Low,
                            description: "The TLS certificate expires within 30 days.".into(),
                            detail: format!("Expires on: {not_after_str} ({days_left} days)"),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }
    }

    findings
}
