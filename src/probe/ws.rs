use crate::Error;
use rand::seq::SliceRandom;

const WS_PATHS: &[&str] = &["/ws", "/ws/v1", "/socket.io", "/chat", "/websocket", "/api/ws"];

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
];

/// Probe a URL for WebSocket endpoint support.
/// Returns the path if WebSocket is detected, None otherwise.
pub async fn probe_ws(base_url: &str) -> Result<Vec<String>, Error> {
    let base = base_url.trim_end_matches('/');
    let ua = USER_AGENTS.choose(&mut rand::thread_rng()).unwrap_or(&USER_AGENTS[0]);
    let mut found = Vec::new();

    for path in WS_PATHS {
        let url = format!("{base}{path}");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()?;

        let resp = match client.get(&url).header("User-Agent", *ua).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = resp.status().as_u16();

        // WebSocket upgrade response or valid endpoint
        if status == 426 || status == 101 {
            found.push(url);
            continue;
        }

        // Check upgrade header
        if let Some(upgrade) = resp.headers().get("upgrade") {
            if upgrade.to_str().unwrap_or("").to_lowercase().contains("websocket") {
                found.push(url);
                continue;
            }
        }

        // Also check Sec-WebSocket-Accept header (confirms WS upgrade)
        if resp.headers().contains_key("sec-websocket-accept") {
            found.push(url);
        }
    }

    Ok(found)
}
