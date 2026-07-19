use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// A scan target: URL, hostname, or IP.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub raw: String,
    pub url: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
}

/// Result of an HTTP probe against a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub target: String,
    pub url: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body_preview: String,
    pub content_length: usize,
    pub response_time: Duration,
    pub title: Option<String>,
    pub tech: Vec<String>,
    pub tls: Option<TlsInfo>,
    pub error: Option<String>,
}

/// TLS certificate information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub domain: String,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub sans: Vec<String>,
    pub self_signed: bool,
}

/// A vulnerability check definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
    pub matchers: Matchers,
}

/// Severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

/// Collection of matchers for a check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matchers {
    pub status: Option<Vec<u16>>,
    pub header_present: Option<Vec<String>>,
    pub header_absent: Option<Vec<String>>,
    pub body_regex: Option<Vec<String>>,
    pub body_contains: Option<Vec<String>>,
    pub title_contains: Option<Vec<String>>,
}

/// Result of running a check against a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub target: String,
    pub check_id: String,
    pub check_name: String,
    pub severity: Severity,
    pub description: String,
    pub detail: String,
    pub timestamp: String,
}

/// Scan configuration.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub threads: usize,
    pub timeout_secs: u64,
    pub rate_limit: u32,
    pub follow_redirects: bool,
    pub insecure: bool,
    pub proxy: Option<String>,
    pub headers: Vec<String>,
    pub ghost: bool,
    pub output_file: Option<String>,
    pub output_format: OutputFormat,
    pub severity_filter: Option<Severity>,
}

/// Supported output formats.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
}
