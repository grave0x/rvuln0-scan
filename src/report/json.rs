use crate::types::Finding;

/// Render findings as JSON.
pub fn format_json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, Severity};

    fn sample_finding() -> Finding {
        Finding {
            target: "http://test.local".into(),
            check_id: "test-check".into(),
            check_name: "Test Check".into(),
            severity: Severity::High,
            description: "A test finding".into(),
            detail: "detail".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn test_json_empty() {
        let out = format_json(&[]);
        assert_eq!(out, "[]");
    }

    #[test]
    fn test_json_one_finding() {
        let out = format_json(&[sample_finding()]);
        assert!(out.contains("test-check"));
        assert!(out.contains("High"));
        assert!(out.contains("http://test.local"));
    }

    #[test]
    fn test_json_valid() {
        let out = format_json(&[sample_finding()]);
        // Verify it parses back
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 1);
    }
}
