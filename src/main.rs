mod check;
mod cli;
mod config;
mod error;
mod probe;
mod report;
mod types;

use clap::Parser;
use check::loader::load_checks;
use cli::{Cli, Command};
use config::{load_config, parse_severity};
use error::Error;
use probe::probe_http;
use report::format_findings;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

fn init_tls() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[tokio::main]
async fn main() {
    init_tls();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp(None)
        .init();

    let cli = Cli::parse();

    // Load config file if specified
    if let Some(ref cfg_path) = cli.config {
        match load_config(cfg_path) {
            Ok(cfg) => {
                for (k, v) in &cfg {
                    log::debug!("Config: {k} = {v}");
                }
            }
            Err(e) => {
                log::error!("{e}");
            }
        }
    }

    let result = match cli.command {
        Command::Probe {
            url,
            timeout,
            follow_redirects,
            insecure,
            proxy,
            header,
            ghost,
            json,
            paths,
            verbose,
        } => {
            cmd_probe(url, timeout, follow_redirects, insecure, proxy, &header, ghost, json, paths, verbose).await
        }
        Command::Check {
            url,
            severity,
            format,
            output,
            timeout,
            follow_redirects,
            insecure,
            proxy,
            header,
            ghost,
            paths,
            check_file,
            verbose,
        } => {
            cmd_check(url, severity, &format, output, timeout, follow_redirects, insecure, proxy, &header, ghost, paths, check_file, verbose).await
        }
        Command::Scan {
            list,
            format,
            output,
            threads,
            severity,
            timeout,
            rate_limit,
            insecure,
            proxy,
            ghost,
            check_file,
            verbose,
        } => {
            cmd_scan(list, &format, output, threads, severity, timeout, rate_limit, insecure, proxy, ghost, check_file, verbose).await
        }
    };

    if let Err(e) = result {
        log::error!("{e}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_probe(
    url: String,
    timeout: u64,
    follow_redirects: bool,
    insecure: bool,
    proxy: Option<String>,
    headers: &[String],
    ghost: bool,
    json: bool,
    paths: Option<String>,
    verbose: bool,
) -> Result<(), Error> {
    _ = verbose;
    let targets = expand_paths(&url, paths);

    for target in &targets {
        if json {
            let result = probe_http(target, timeout, follow_redirects, insecure, proxy.as_deref(), headers, ghost, true).await?;
            let tech = probe::tech::detect_tech(&result);
            let mut output = serde_json::json!({
                "url": result.url,
                "status": result.status_code,
                "content_length": result.content_length,
                "response_time_ms": result.response_time.as_millis(),
                "title": result.title,
                "tech": tech,
            });
            if let Some(ref tls) = result.tls {
                output["tls"] = serde_json::json!({
                    "issuer": tls.issuer,
                    "subject": tls.subject,
                    "not_before": tls.not_before,
                    "not_after": tls.not_after,
                    "sans": tls.sans,
                });
            }
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            let result = probe_http(target, timeout, follow_redirects, insecure, proxy.as_deref(), headers, ghost, true).await?;
            let tech = probe::tech::detect_tech(&result);

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
            if let Some(ref tls) = result.tls {
                if let Some(ref issuer) = tls.issuer {
                    println!("TLS Issuer: {issuer}");
                }
                if let Some(ref subject) = tls.subject {
                    println!("TLS Subject: {subject}");
                }
                if let Some(ref nb) = tls.not_before {
                    println!("TLS Valid From: {nb}");
                }
                if let Some(ref na) = tls.not_after {
                    println!("TLS Valid Until: {na}");
                }
                if !tls.sans.is_empty() {
                    println!("TLS SANs: {}", tls.sans.join(", "));
                }
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_check(
    url: String,
    severity: Option<String>,
    format: &str,
    output: Option<String>,
    timeout: u64,
    follow_redirects: bool,
    insecure: bool,
    proxy: Option<String>,
    headers: &[String],
    ghost: bool,
    paths: Option<String>,
    check_file: Option<String>,
    verbose: bool,
) -> Result<(), Error> {
    _ = verbose;
    let targets = expand_paths(&url, paths);
    let sev = parse_severity(severity.as_deref());
    let extra = load_extra_checks(check_file);
    let mut all_findings = Vec::new();

    for target in &targets {
        if targets.len() > 1 {
            log::info!("Checking {target}");
        }
        match probe_http(target, timeout, follow_redirects, insecure, proxy.as_deref(), headers, ghost, true).await {
            Ok(probe) => {
                let findings = check::run_checks(&probe, sev, &extra).await;
                all_findings.extend(findings);
            }
            Err(e) => {
                log::error!("Failed to probe {target}: {e}");
            }
        }
    }

    let output_str = format_findings(&all_findings, format);
    if let Some(path) = output {
        fs::write(&path, &output_str).await.map_err(Error::Io)?;
        log::info!("Written {} findings to {path}", all_findings.len());
    } else {
        print!("{output_str}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_scan(
    list: String,
    format: &str,
    output: Option<String>,
    threads: usize,
    severity: Option<String>,
    timeout: u64,
    rate_limit: u32,
    insecure: bool,
    proxy: Option<String>,
    ghost: bool,
    check_file: Option<String>,
    verbose: bool,
) -> Result<(), Error> {
    let content = fs::read_to_string(&list).await.map_err(Error::Io)?;
    let targets: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    if targets.is_empty() {
        return Err(Error::NoTargets);
    }

    log::info!("Scanning {} targets (threads={}, rate={}/s)", targets.len(), threads, rate_limit);

    let sev = parse_severity(severity.as_deref());
    let extra = load_extra_checks(check_file);
    let semaphore = Arc::new(Semaphore::new(threads));
    let counter = Arc::new(AtomicUsize::new(0));
    let total = targets.len();
    let rate_delay = if rate_limit > 0 {
        Duration::from_secs_f64(1.0 / rate_limit as f64)
    } else {
        Duration::ZERO
    };
    let mut handles = Vec::new();

    for target in targets {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let proxy = proxy.clone();
        let counter = counter.clone();
        let extra = extra.clone();

        if rate_delay > Duration::ZERO {
            sleep(rate_delay).await;
        }

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            match probe_http(&target, timeout, true, insecure, proxy.as_deref(), &[], ghost, false).await {
                Ok(probe) => {
                    let findings = check::run_checks(&probe, sev, &extra).await;
                    let done = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    if verbose || done.is_multiple_of(10) || done == total {
                        log::info!("Scan progress: {done}/{total}");
                    }
                    (target, findings)
                }
                Err(e) => {
                    let done = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    log::error!("Failed {target}: {e}");
                    if verbose || done.is_multiple_of(10) || done == total {
                        log::info!("Scan progress: {done}/{total}");
                    }
                    (target, vec![])
                }
            }
        }));
    }

    let mut all_findings = Vec::new();
    for h in handles {
        if let Ok((_target, findings)) = h.await {
            all_findings.extend(findings);
        }
    }

    log::info!("Scan complete. {} finding(s) found.", all_findings.len());

    let output_str = format_findings(&all_findings, format);
    if let Some(path) = output {
        fs::write(&path, &output_str).await.map_err(Error::Io)?;
        log::info!("Results written to {path}");
    } else {
        print!("{output_str}");
    }
    Ok(())
}

/// Load YAML checks from an optional file path.
fn load_extra_checks(path: Option<String>) -> Vec<types::Check> {
    match path {
        Some(p) => match load_checks(&p) {
            Ok(checks) => {
                log::info!("Loaded {} custom check(s) from {p}", checks.len());
                checks
            }
            Err(e) => {
                log::error!("{e}");
                vec![]
            }
        },
        None => vec![],
    }
}

/// Expand a base URL with additional paths for multi-path probing.
fn expand_paths(base: &str, paths: Option<String>) -> Vec<String> {
    let paths = match paths {
        Some(p) => p.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>(),
        None => return vec![base.to_string()],
    };
    if paths.is_empty() {
        return vec![base.to_string()];
    }
    let base = base.trim_end_matches('/');
    let mut result = Vec::with_capacity(paths.len() + 1);
    result.push(base.to_string());
    for p in paths {
        let full = if p.starts_with('/') {
            format!("{base}{p}")
        } else {
            format!("{base}/{p}")
        };
        result.push(full);
    }
    result
}
