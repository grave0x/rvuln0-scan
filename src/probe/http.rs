use crate::types::ProbeResult;
use crate::error::Error;
use rand::seq::SliceRandom;
use reqwest::header::{HeaderValue, USER_AGENT};
use reqwest::Client;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;

const DEFAULT_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:121.0) Gecko/20100101 Firefox/121.0",
];

fn pick_user_agent() -> &'static str {
    DEFAULT_USER_AGENTS
        .choose(&mut rand::thread_rng())
        .unwrap_or(&DEFAULT_USER_AGENTS[0])
}

fn build_client(
    timeout_secs: u64,
    follow_redirects: bool,
    insecure: bool,
    proxy: Option<&str>,
) -> Result<Client, Error> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(insecure);

    if !follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    if let Some(p) = proxy {
        let proxy =
            reqwest::Proxy::all(p).map_err(|_| Error::Parse(format!("Invalid proxy URL: {p}")))?;
        builder = builder.proxy(proxy);
    }

    Ok(builder.build()?)
}

/// Probe a single URL: fetch headers + response body preview.
pub async fn probe_http(
    url: &str,
    timeout_secs: u64,
    follow_redirects: bool,
    insecure: bool,
    proxy: Option<&str>,
    extra_headers: &[String],
    ghost_mode: bool,
) -> Result<ProbeResult, Error> {
    let client = build_client(timeout_secs, follow_redirects, insecure, proxy)?;

    let mut req = client.get(url);

    let ua = if ghost_mode {
        pick_user_agent()
    } else {
        DEFAULT_USER_AGENTS[0]
    };
    req = req.header(USER_AGENT, HeaderValue::from_str(ua).unwrap());

    for h in extra_headers {
        if let Some((key, val)) = h.split_once(':') {
            let k = key.trim();
            let v = val.trim();
            req = req.header(k, v);
        }
    }

    let start = Instant::now();
    let resp = req.send().await.map_err(Error::Http)?;
    let response_time = start.elapsed();

    let status_code = resp.status().as_u16();
    let headers: HashMap<String, String> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body_bytes = resp.bytes().await.map_err(Error::Http)?;
    let content_length = body_bytes.len();
    let body_str = String::from_utf8_lossy(&body_bytes[..content_length.min(512)]).to_string();

    let title = extract_title(&body_str);

    if ghost_mode {
        let jitter_ms = rand::random::<u64>() % 500;
        sleep(Duration::from_millis(jitter_ms)).await;
    }

    Ok(ProbeResult {
        target: url.to_string(),
        url: url.to_string(),
        status_code,
        headers,
        body_preview: body_str,
        content_length,
        response_time,
        title,
        tech: Vec::new(),
        tls: None,
        error: None,
    })
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let open = "<title>";
    let close = "</title>";
    if let Some(start) = lower.find(open) {
        let s = start + open.len();
        if let Some(end) = lower[s..].find(close) {
            let title = body[s..s + end].trim().to_string();
            if !title.is_empty() {
                return Some(title);
            }
        }
    }
    None
}
