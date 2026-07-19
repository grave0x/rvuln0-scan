pub mod table;
pub mod json;
pub mod sarif;
pub mod html;

use crate::types::Finding;

/// Format findings according to the specified format.
pub fn format_findings(findings: &[Finding], format: &str) -> String {
    match format {
        "json" => json::format_json(findings),
        "sarif" => sarif::format_sarif(findings),
        "html" => html::format_html(findings),
        _ => table::format_table(findings),
    }
}
