use crate::types::{Finding, Severity};

/// Filter findings by minimum severity.
pub fn by_severity(findings: Vec<Finding>, min: Severity) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| f.severity.rank() >= min.rank())
        .collect()
}
