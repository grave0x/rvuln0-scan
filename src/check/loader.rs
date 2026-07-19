use crate::types::{Check, Matchers, Severity};
use serde::Deserialize;

/// A check definition as stored in YAML.
#[derive(Debug, Deserialize)]
struct YamlCheck {
    id: String,
    name: String,
    severity: String,
    description: String,
    #[serde(default)]
    matchers: YamlMatchers,
}

#[derive(Debug, Deserialize, Default)]
struct YamlMatchers {
    status: Option<Vec<u16>>,
    header_present: Option<Vec<String>>,
    header_absent: Option<Vec<String>>,
    body_regex: Option<Vec<String>>,
    body_contains: Option<Vec<String>>,
    title_contains: Option<Vec<String>>,
}

/// Load vulnerability checks from a YAML file.
/// Expected format: a list of check definitions.
pub fn load_checks(path: &str) -> Result<Vec<Check>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let yaml_checks: Vec<YamlCheck> =
        serde_yaml::from_str(&content).map_err(|e| format!("YAML parse error in {path}: {e}"))?;

    let mut checks = Vec::with_capacity(yaml_checks.len());
    for yc in yaml_checks {
        let severity = match yc.severity.to_lowercase().as_str() {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => return Err(format!("Unknown severity '{other}' in check '{}'", yc.id)),
        };
        checks.push(Check {
            id: yc.id,
            name: yc.name,
            severity,
            description: yc.description,
            matchers: Matchers {
                status: yc.matchers.status,
                header_present: yc.matchers.header_present,
                header_absent: yc.matchers.header_absent,
                body_regex: yc.matchers.body_regex,
                body_contains: yc.matchers.body_contains,
                title_contains: yc.matchers.title_contains,
            },
        });
    }
    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_yaml_checks() {
        let yaml = r#"
        - id: test-check
          name: Test Check
          severity: high
          description: A test
          matchers:
            status: [200, 301]
            body_contains: ["admin"]
        "#;
        let checks: Vec<YamlCheck> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].id, "test-check");
        assert_eq!(checks[0].matchers.status, Some(vec![200, 301]));
    }
}
