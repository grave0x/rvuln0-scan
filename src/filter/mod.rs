use crate::types::{Finding, Severity};

/// Filter findings by minimum severity.
#[allow(dead_code)]
pub fn by_severity(findings: Vec<Finding>, min: Severity) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| f.severity.rank() >= min.rank())
        .collect()
}
