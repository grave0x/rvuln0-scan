pub mod matcher;
pub mod builtin;
pub mod loader;

use crate::types::{Check, Finding, ProbeResult, Severity};
use crate::probe::probe_http;

/// Run all applicable checks against a probe result.
/// For checks with a `path` set, probes that path on the target.
pub async fn run_checks(
    probe: &ProbeResult,
    min_severity: Option<Severity>,
    extra_checks: &[Check],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let min = min_severity;

    // Build combined check list
    let mut combined = builtin::all_checks();
    combined.extend_from_slice(extra_checks);

    for check in &combined {
        if let Some(m) = min {
            if check.severity.rank() < m.rank() {
                continue;
            }
        }

        // Determine which ProbeResult to match against
        let target_probe = if let Some(ref path) = check.matchers.path {
            // Path-based check: probe the specific path
            let base = probe.url.trim_end_matches('/');
            let full_url = if path.starts_with('/') {
                format!("{base}{path}")
            } else {
                format!("{base}/{path}")
            };
            match probe_http(&full_url, 5, false, false, None, &[], false, false).await {
                Ok(path_probe) => path_probe,
                Err(_) => continue,
            }
        } else {
            // Main page check: use the existing probe result (need to clone since match is consumed)
            // Actually we just pass a reference to the original probe
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
            continue;
        };

        // Match against the path probe result
        if matcher::matches(check, &target_probe) {
            findings.push(Finding {
                target: target_probe.target.clone(),
                check_id: check.id.clone(),
                check_name: check.name.clone(),
                severity: check.severity,
                description: check.description.clone(),
                detail: format!("Matched on {} ({})", target_probe.url, target_probe.status_code),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    // TLS checks (always run against the main probe)
    if let Some(ref tls) = probe.tls {
        if tls.self_signed && min.is_none_or(|m| Severity::Medium.rank() >= m.rank()) {
            findings.push(Finding {
                target: probe.target.clone(), check_id: "tls-self-signed".into(),
                check_name: "Self-Signed Certificate".into(), severity: Severity::Medium,
                description: "The server uses a self-signed TLS certificate.".into(),
                detail: format!("Subject: {:?}", tls.subject),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }

        if let Some(ref na) = tls.not_after {
            if min.is_none_or(|m| Severity::High.rank() >= m.rank()) {
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc2822(na) {
                    let expiry_utc = expiry.with_timezone(&chrono::Utc);
                    let days_left = (expiry_utc - chrono::Utc::now()).num_days();
                    if days_left < 0 {
                        findings.push(Finding {
                            target: probe.target.clone(), check_id: "tls-expired".into(),
                            check_name: "Expired Certificate".into(), severity: Severity::High,
                            description: "The TLS certificate has expired.".into(),
                            detail: format!("Expired on: {na}"),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        });
                    } else if days_left < 30 {
                        findings.push(Finding {
                            target: probe.target.clone(), check_id: "tls-expiring-soon".into(),
                            check_name: "Certificate Expiring Soon".into(), severity: Severity::Low,
                            description: "The TLS certificate expires within 30 days.".into(),
                            detail: format!("Expires on: {na} ({days_left} days)"),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }
    }

    findings
}
