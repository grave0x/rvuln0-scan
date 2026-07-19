use crate::types::Finding;

/// Render findings as JSON.
pub fn format_json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string())
}
