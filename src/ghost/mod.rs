#![allow(dead_code)]

use rand::seq::SliceRandom;
use rand::Rng;
use std::time::Duration;
use tokio::time::sleep;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
];

/// Pick a random user agent.
pub fn random_ua() -> &'static str {
    USER_AGENTS.choose(&mut rand::thread_rng()).unwrap_or(&USER_AGENTS[0])
}

/// Sleep for a random jitter duration (0-500ms).
pub async fn jitter() {
    let ms: u64 = rand::thread_rng().gen_range(0..500);
    sleep(Duration::from_millis(ms)).await;
}
