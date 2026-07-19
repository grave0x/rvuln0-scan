use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("No targets provided")]
    NoTargets,

    #[error("Rate limit exceeded")]
    RateLimited,
}
