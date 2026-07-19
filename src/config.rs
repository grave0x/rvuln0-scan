use crate::types::{OutputFormat, ScanConfig, Severity};
use std::collections::HashMap;

/// Build a ScanConfig from raw CLI values.
/// This function is kept for future YAML config loading.
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
        Some(other) => return Err(format!("Unknown output format: {other}")),
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

/// Parse a severity string into a Severity value.
pub fn parse_severity(s: Option<&str>) -> Option<Severity> {
    match s {
        Some("info") => Some(Severity::Info),
        Some("low") => Some(Severity::Low),
        Some("medium") => Some(Severity::Medium),
        Some("high") => Some(Severity::High),
        Some("critical") => Some(Severity::Critical),
        _ => None,
    }
}

/// Load default settings from a TOML config file.
/// Returns a map of key-value pairs.
pub fn load_config(path: &str) -> Result<HashMap<String, String>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read config: {e}"))?;
    let parsed: HashMap<String, String> = content
        .lines()
        .filter(|l| l.contains('=') && !l.trim().starts_with('#'))
        .filter_map(|l| {
            let mut parts = l.splitn(2, '=');
            let key = parts.next()?.trim().to_string();
            let val = parts.next()?.trim().trim_matches('"').to_string();
            Some((key, val))
        })
        .collect();
    Ok(parsed)
}
