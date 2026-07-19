use crate::types::Finding;

/// Render findings as a standalone HTML page.
pub fn format_html(findings: &[Finding]) -> String {
    let count = findings.len();
    let rows: String = findings
        .iter()
        .map(|f| {
            let sev_class = match f.severity.rank() {
                0..=1 => "info",
                2 => "medium",
                3 => "high",
                _ => "critical",
            };
            format!(
                r#"<tr class="{sev_class}"><td>{sev}</td><td>{id}</td><td>{target}</td><td>{desc}</td></tr>"#,
                sev = format_args!("{:?}", f.severity),
                id = f.check_id,
                target = f.target,
                desc = f.description,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>rvuln0-scan Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }}
h1 {{ font-size: 1.5rem; color: #333; }}
.summary {{ margin: 1rem 0; padding: 1rem; background: #f5f5f5; border-radius: 4px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 0.5rem; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background: #f0f0f0; }}
tr.critical {{ background: #fff0f0; }} tr.high {{ background: #fff8f0; }}
tr.medium {{ background: #fffff0; }} tr.info {{ background: #f8f8ff; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.8rem; color: #fff; }}
.badge-Critical {{ background: #d32f2f; }} .badge-High {{ background: #f57c00; }}
.badge-Medium {{ background: #fbc02d; }} .badge-Low,.badge-Info {{ background: #757575; }}
</style></head>
<body>
<h1>rvuln0-scan Report</h1>
<div class="summary">Found <strong>{count}</strong> finding(s)</div>
<table><thead><tr><th>Severity</th><th>Check</th><th>Target</th><th>Description</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"#,
    )
}
