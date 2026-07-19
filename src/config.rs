use crate::types::{OutputFormat, ScanConfig, Severity};
use serde::Deserialize;

/// Config file format (YAML).
#[derive(Debug, Deserialize, Default)]
pub struct FileConfig {
    pub threads: Option<usize>,
    pub timeout: Option<u64>,
    pub rate_limit: Option<u32>,
    pub proxy: Option<String>,
    pub ghost: Option<bool>,
    pub insecure: Option<bool>,
    pub format: Option<String>,
    #[allow(dead_code)]
    pub severity: Option<String>,
    #[allow(dead_code)]
    pub header: Option<Vec<String>>,
}

/// Parse a severity string into a Severity value.
pub fn parse_severity(s: Option<&str>) -> Option<Severity> {
    match s {
        Some("info") => Some(Severity::Info), Some("low") => Some(Severity::Low),
        Some("medium") => Some(Severity::Medium), Some("high") => Some(Severity::High),
        Some("critical") => Some(Severity::Critical), _ => None,
    }
}

/// Load settings from a YAML config file.
pub fn load_config(path: &str) -> Result<FileConfig, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read config: {e}"))?;
    let cfg: FileConfig = serde_yaml::from_str(&content).map_err(|e| format!("Config parse error: {e}"))?;
    Ok(cfg)
}

#[allow(dead_code)]
impl FileConfig {
    pub fn threads_or(&self, cli_threads: Option<usize>) -> usize {
        cli_threads.or(self.threads).unwrap_or(25)
    }
    pub fn timeout_or(&self, cli_timeout: Option<u64>) -> u64 {
        cli_timeout.or(self.timeout).unwrap_or(10)
    }
    pub fn rate_limit_or(&self, cli_rate: Option<u32>) -> u32 {
        cli_rate.or(self.rate_limit).unwrap_or(100)
    }
    pub fn proxy_or(&self, cli_proxy: Option<String>) -> Option<String> {
        cli_proxy.or_else(|| self.proxy.clone())
    }
}

/// Build a ScanConfig from raw CLI values.
/// This function is kept for future use.
#[allow(dead_code, clippy::too_many_arguments)]
pub fn build_config(
    targets: Vec<String>, threads: Option<usize>, timeout: Option<u64>,
    rate_limit: Option<u32>, follow_redirects: bool, insecure: bool,
    proxy: Option<String>, headers: Vec<String>, ghost: bool,
    output_file: Option<String>, output_format: Option<String>, severity: Option<String>,
) -> Result<ScanConfig, String> {
    let fmt = match output_format.as_deref() {
        Some("json") => OutputFormat::Json, Some("table") | None => OutputFormat::Table,
        Some(other) => return Err(format!("Unknown output format: {other}")),
    };
    let sev = match severity.as_deref() {
        Some("info") => Some(Severity::Info), Some("low") => Some(Severity::Low),
        Some("medium") => Some(Severity::Medium), Some("high") => Some(Severity::High),
        Some("critical") => Some(Severity::Critical), Some(other) => return Err(format!("Unknown severity: {other}")),
        None => None,
    };
    Ok(ScanConfig { targets, threads: threads.unwrap_or(25), timeout_secs: timeout.unwrap_or(10), rate_limit: rate_limit.unwrap_or(100), follow_redirects, insecure, proxy, headers, ghost, output_file, output_format: fmt, severity_filter: sev })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity(Some("high")), Some(Severity::High));
        assert_eq!(parse_severity(Some("info")), Some(Severity::Info));
        assert_eq!(parse_severity(Some("invalid")), None);
        assert_eq!(parse_severity(None), None);
    }

    #[test]
    fn test_load_yaml_config() {
        let yaml = "threads: 50\ntimeout: 30\nghost: true\nformat: json\n";
        let cfg: FileConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.threads, Some(50));
        assert_eq!(cfg.timeout, Some(30));
        assert_eq!(cfg.ghost, Some(true));
        assert_eq!(cfg.format, Some("json".into()));
    }

    #[test]
    fn test_file_config_merge() {
        let cfg = FileConfig { threads: Some(50), ..Default::default() };
        assert_eq!(cfg.threads_or(None), 50);
        assert_eq!(cfg.threads_or(Some(100)), 100); // CLI overrides
    }
}
