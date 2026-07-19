use crate::types::Finding;

/// Render findings as a terminal table.
pub fn format_table(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No findings.\n".to_string();
    }

    let sev_width = 10;
    let id_width = 30;
    let desc_width = 50;
    let sep = format!("{:-<1$}+{:-<2$}+{:-<3$}\n", "", sev_width + 2, id_width + 2, desc_width + 2);

    let mut out = String::new();
    out.push_str(&format!(
        " {:<width$} | {:<width2$} | {:<width3$}\n",
        "Severity", "Check ID", "Target",
        width = sev_width, width2 = id_width, width3 = desc_width
    ));
    out.push_str(&sep);

    for f in findings {
        let sev_str = format!("{:?}", f.severity);
        out.push_str(&format!(
            " {:<sev$} | {:<id$} | {:<desc$}\n",
            sev_str, f.check_id, f.target,
            sev = sev_width, id = id_width, desc = desc_width
        ));
    }

    out.push_str(&format!("\n{} finding(s) found.\n", findings.len()));
    out
}
