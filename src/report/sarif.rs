use crate::types::Finding;
use serde::Serialize;

#[derive(Serialize)]
struct SarifLog {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<Run>,
}

#[derive(Serialize)]
struct Run {
    tool: Tool,
    results: Vec<Result>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
struct Driver {
    name: String,
    version: String,
    information_uri: String,
}

#[derive(Serialize)]
struct Result {
    rule_id: String,
    level: String,
    message: Message,
    locations: Vec<Location>,
}

#[derive(Serialize)]
struct Message {
    text: String,
}

#[derive(Serialize)]
struct Location {
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

/// Render findings as SARIF (Static Analysis Results Interchange Format).
pub fn format_sarif(findings: &[Finding]) -> String {
    let log = SarifLog {
        version: "2.1.0".into(),
        schema: "https://schemastore.azurewebsites.net/schemas/2.1.0/sarif-2.1.0.json".into(),
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "rvuln0-scan".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    information_uri: "https://github.com/grave/Projects/rvuln0-scan".into(),
                },
            },
            results: findings
                .iter()
                .map(|f| Result {
                    rule_id: f.check_id.clone(),
                    level: match f.severity.rank() {
                        0 => "note".into(),
                        1 => "note".into(),
                        2 => "warning".into(),
                        3 => "error".into(),
                        _ => "error".into(),
                    },
                    message: Message {
                        text: format!("{}: {}", f.check_name, f.description),
                    },
                    locations: vec![Location {
                        physical_location: PhysicalLocation {
                            artifact_location: ArtifactLocation {
                                uri: f.target.clone(),
                            },
                        },
                    }],
                })
                .collect(),
        }],
    };

    serde_json::to_string_pretty(&log).unwrap_or_else(|_| "{}".to_string())
}
