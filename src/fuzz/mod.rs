pub mod wordlist;

use crate::error::Error;
use crate::probe::probe_http;
use crate::types::Finding;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Run a fuzz scan against a base URL.
/// Probes each wordlist path and returns findings for discovered paths.
pub async fn run_fuzz(
    base_url: &str,
    threads: usize,
    timeout: u64,
    insecure: bool,
    status_filter: Vec<u16>,
) -> Result<Vec<Finding>, Error> {
    let base = base_url.trim_end_matches('/');
    let semaphore = Arc::new(Semaphore::new(threads));
    let mut handles = Vec::new();

    for path in wordlist::WORDLIST {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let url = if path.starts_with('/') {
            format!("{base}{path}")
        } else {
            format!("{base}/{path}")
        };

        let sf = status_filter.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            match probe_http(&url, timeout, false, insecure, None, &[], false, false).await {
                Ok(result) => {
                    if sf.is_empty() || sf.contains(&result.status_code) {
                        Some(Finding {
                            target: url.clone(),
                            check_id: "fuzz-discovered".into(),
                            check_name: "Discovered Path".into(),
                            severity: crate::types::Severity::Info,
                            description: "A path or file was discovered during fuzzing.".into(),
                            detail: format!("Status: {} ({} bytes)", result.status_code, result.content_length),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            risk_score: Finding::calc_risk_score(&crate::types::Severity::Info),
                        })
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        }));
    }

    let mut findings = Vec::new();
    for h in handles {
        if let Ok(Some(f)) = h.await {
            findings.push(f);
        }
    }

    Ok(findings)
}
