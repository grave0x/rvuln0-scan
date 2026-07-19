use crate::types::Finding;

/// Render findings as JSON.
pub fn format_json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    fn f() -> Finding {
        Finding {
            target: "http://test.local".into(), check_id: "t".into(), check_name: "T".into(),
            severity: Severity::High, description: "d".into(), detail: "d".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test] fn test_empty() { assert_eq!(format_json(&[]), "[]"); }
    #[test] fn test_one() { let j = format_json(&[f()]); assert!(j.contains("High")); assert!(j.contains("http://test.local")); }
    #[test] fn test_valid_json() { let j = format_json(&[f()]); assert!(serde_json::from_str::<Vec<serde_json::Value>>(&j).is_ok()); }
}
