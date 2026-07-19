pub mod table;
pub mod json;

use crate::types::Finding;

/// Format findings according to the specified format.
pub fn format_findings(findings: &[Finding], format: &str) -> String {
    match format {
        "json" => json::format_json(findings),
        _ => table::format_table(findings),
    }
}
