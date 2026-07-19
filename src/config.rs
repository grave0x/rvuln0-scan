use crate::types::{OutputFormat, ScanConfig, Severity};

/// Build ScanConfig from raw CLI values.
#[allow(dead_code, clippy::too_many_arguments)]
pub fn build_config(
    targets: Vec<String>,
    threads: Option<usize>,
    timeout: Option<u64>,
    rate_limit: Option<u32>,
    follow_redirects: bool,
    insecure: bool,
    proxy: Option<String>,
    headers: Vec<String>,
    ghost: bool,
    output_file: Option<String>,
    output_format: Option<String>,
    severity: Option<String>,
) -> Result<ScanConfig, String> {
    let fmt = match output_format.as_deref() {
        Some("json") => OutputFormat::Json,
        Some("table") | None => OutputFormat::Table,
        Some(other) => {
            return Err(format!(
                "Unknown output format: {other}. Use 'table' or 'json'."
            ))
        }
    };

    let sev = match severity.as_deref() {
        Some("info") => Some(Severity::Info),
        Some("low") => Some(Severity::Low),
        Some("medium") => Some(Severity::Medium),
        Some("high") => Some(Severity::High),
        Some("critical") => Some(Severity::Critical),
        Some(other) => return Err(format!("Unknown severity: {other}")),
        None => None,
    };

    Ok(ScanConfig {
        targets,
        threads: threads.unwrap_or(25),
        timeout_secs: timeout.unwrap_or(10),
        rate_limit: rate_limit.unwrap_or(100),
        follow_redirects,
        insecure,
        proxy,
        headers,
        ghost,
        output_file,
        output_format: fmt,
        severity_filter: sev,
    })
}
