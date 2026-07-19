use rvuln0_scan::check;
use rvuln0_scan::cli::{Cli, Command};
use rvuln0_scan::error::Error;
use rvuln0_scan::probe::probe_http;
use rvuln0_scan::report::format_findings;
use rvuln0_scan::types::Severity;
use clap::Parser;
use tokio::sync::Semaphore;
use std::sync::Arc;
use tokio::fs;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Probe { url, timeout, follow_redirects, insecure, proxy, header, ghost } => {
            cmd_probe(url, timeout, follow_redirects, insecure, proxy.as_deref(), &header, ghost).await
        }
        Command::Check { url, severity, format, output, timeout, follow_redirects, insecure, proxy, header, ghost } => {
            cmd_check(url, severity, &format, output, timeout, follow_redirects, insecure, proxy.as_deref(), &header, ghost).await
        }
        Command::Scan { list, format, output, threads, severity, timeout, rate_limit: _, insecure, proxy, ghost } => {
            cmd_scan(list, &format, output, threads, severity, timeout, insecure, proxy, ghost).await
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn cmd_probe(
    url: String, timeout: u64, follow_redirects: bool, insecure: bool,
    proxy: Option<&str>, headers: &[String], ghost: bool,
) -> Result<(), Error> {
    let result = probe_http(&url, timeout, follow_redirects, insecure, proxy, headers, ghost).await?;
    let tech = rvuln0_scan::detect_tech_blocking(&result);

    println!("URL: {}", result.url);
    println!("Status: {}", result.status_code);
    println!("Content-Length: {}", result.content_length);
    println!("Response Time: {:?}", result.response_time);
    if let Some(ref title) = result.title {
        println!("Title: {title}");
    }
    if !tech.is_empty() {
        println!("Tech: {}", tech.join(", "));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_check(
    url: String, severity: Option<String>, format: &str, output: Option<String>,
    timeout: u64, follow_redirects: bool, insecure: bool,
    proxy: Option<&str>, headers: &[String], ghost: bool,
) -> Result<(), Error> {
    let probe = probe_http(&url, timeout, follow_redirects, insecure, proxy, headers, ghost).await?;
    let sev = severity.as_deref().and_then(|s| match s {
        "info" => Some(Severity::Info), "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium), "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical), _ => None,
    });
    let findings = check::run_checks(&probe, sev).await;
    let output_str = format_findings(&findings, format);
    if let Some(path) = output {
        fs::write(&path, &output_str).await.map_err(Error::Io)?;
    } else {
        print!("{output_str}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_scan(
    list: String, format: &str, output: Option<String>, threads: usize,
    severity: Option<String>, timeout: u64, insecure: bool,
    proxy: Option<String>, ghost: bool,
) -> Result<(), Error> {
    let content = fs::read_to_string(&list).await.map_err(Error::Io)?;
    let targets: Vec<String> = content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    if targets.is_empty() {
        return Err(Error::NoTargets);
    }
    let sev = severity.as_deref().and_then(|s| match s {
        "info" => Some(Severity::Info), "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium), "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical), _ => None,
    });
    let semaphore = Arc::new(Semaphore::new(threads));
    let mut handles = Vec::new();
    for target in targets {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let proxy = proxy.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            match probe_http(&target, timeout, true, insecure, proxy.as_deref(), &[], ghost).await {
                Ok(probe) => { let findings = check::run_checks(&probe, sev).await; (target, findings) }
                Err(_) => { (target, vec![]) }
            }
        }));
    }
    let mut all_findings = Vec::new();
    for h in handles {
        if let Ok((_target, findings)) = h.await {
            all_findings.extend(findings);
        }
    }
    let output_str = format_findings(&all_findings, format);
    if let Some(path) = output {
        fs::write(&path, &output_str).await.map_err(Error::Io)?;
    } else {
        print!("{output_str}");
    }
    Ok(())
}
