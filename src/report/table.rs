use crate::types::Finding;

/// Render findings as a terminal table.
pub fn format_table(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No findings.\n".to_string();
    }

    let mut out = String::new();
    out.push_str(&format!(
        " {:<10} | {:<30} | {:<8} | {:<50}\n",
        "Severity", "Check ID", "Risk", "Target"
    ));
    out.push_str(&format!("{:-<102}\n", ""));

    for f in findings {
        let sev_str = format!("{:?}", f.severity);
        let risk_str = format!("{:.0}", f.risk_score);
        out.push_str(&format!(
            " {:<10} | {:<30} | {:>8} | {:<50}\n",
            sev_str, f.check_id, risk_str, f.target
        ));
    }

    out.push_str(&format!("\n{} finding(s) found.\n", findings.len()));
    out
}
