use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rvuln0", version, about = "Fast Rust vulnerability scanner")]
pub struct Cli {
    /// Path to TOML config file with default settings
    #[arg(long, global = true)]
    pub config: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Probe a single URL for HTTP headers, tech, and TLS info
    Probe {
        /// Target URL
        url: String,

        /// Request timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Follow HTTP redirects
        #[arg(long, default_value_t = true)]
        follow_redirects: bool,

        /// Skip TLS certificate verification
        #[arg(short = 'k', long)]
        insecure: bool,

        /// HTTP proxy (e.g. http://127.0.0.1:8080)
        #[arg(long)]
        proxy: Option<String>,

        /// Custom header (can repeat)
        #[arg(short = 'H', long)]
        header: Vec<String>,

        /// Enable ghost mode (random UA, request jitter)
        #[arg(long)]
        ghost: bool,

        /// Output in JSON format
        #[arg(long)]
        json: bool,

        /// Paths to probe (comma-separated)
        #[arg(long)]
        paths: Option<String>,

        /// Verbose output
        #[arg(short = 'v')]
        verbose: bool,
    },

    /// Run vulnerability checks against a target
    Check {
        /// Target URL
        url: String,

        /// Minimum severity to report (info|low|medium|high|critical)
        #[arg(long)]
        severity: Option<String>,

        /// Output format (table|json|sarif|html)
        #[arg(short = 'f', long, default_value = "table")]
        format: String,

        /// Output file
        #[arg(short = 'o', long)]
        output: Option<String>,

        /// Request timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Follow HTTP redirects
        #[arg(long, default_value_t = true)]
        follow_redirects: bool,

        /// Skip TLS certificate verification
        #[arg(short = 'k', long)]
        insecure: bool,

        /// HTTP proxy
        #[arg(long)]
        proxy: Option<String>,

        /// Custom header (can repeat)
        #[arg(short = 'H', long)]
        header: Vec<String>,

        /// Enable ghost mode
        #[arg(long)]
        ghost: bool,

        /// Paths to check (comma-separated)
        #[arg(long)]
        paths: Option<String>,

        /// Path to YAML file with custom checks
        #[arg(short = 'c', long)]
        check_file: Option<String>,

        /// Enable honeypot detection (flags targets with many matches)
        #[arg(long)]
        honeypot_detect: bool,

        /// Suppress findings flagged as honeypots
        #[arg(long)]
        suppress_honeypot: bool,

        /// Verbose output
        #[arg(short = 'v')]
        verbose: bool,
    },

    /// Scan targets from a list file
    Scan {
        /// Path to file with targets (one per line)
        #[arg(short = 'l', long)]
        list: String,

        /// Output format (table|json|sarif|html)
        #[arg(short = 'f', long, default_value = "table")]
        format: String,

        /// Output file
        #[arg(short = 'o', long)]
        output: Option<String>,

        /// Concurrency
        #[arg(short = 't', long, default_value = "25")]
        threads: usize,

        /// Minimum severity
        #[arg(long)]
        severity: Option<String>,

        /// Request timeout
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Rate limit (requests/sec)
        #[arg(long, default_value = "100")]
        rate_limit: u32,

        /// Skip TLS verification
        #[arg(short = 'k', long)]
        insecure: bool,

        /// HTTP proxy
        #[arg(long)]
        proxy: Option<String>,

        /// Ghost mode
        #[arg(long)]
        ghost: bool,

        /// Path to YAML file with custom checks
        #[arg(short = 'c', long)]
        check_file: Option<String>,

        /// Enable honeypot detection
        #[arg(long)]
        honeypot_detect: bool,

        /// Suppress findings flagged as honeypots
        #[arg(long)]
        suppress_honeypot: bool,

        /// Verbose output
        #[arg(short = 'v')]
        verbose: bool,
    },

    /// Fuzz a target URL with a wordlist to discover hidden paths
    Fuzz {
        /// Target base URL
        url: String,

        /// Concurrency
        #[arg(short = 't', long, default_value = "10")]
        threads: usize,

        /// Request timeout in seconds
        #[arg(long, default_value = "5")]
        timeout: u64,

        /// Skip TLS verification
        #[arg(short = 'k', long)]
        insecure: bool,

        /// Only show results matching these status codes (comma-separated)
        #[arg(long, default_value = "200,201,204,301,302,307,401,403,405,500")]
        status_filter: String,

        /// Verbose output
        #[arg(short = 'v')]
        verbose: bool,
    },
}
