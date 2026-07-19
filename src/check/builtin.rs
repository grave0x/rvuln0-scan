use crate::types::{Check, Severity, Matchers};

/// Helper to create Matchers.
fn m(
    status: Option<Vec<u16>>,
    hp: Option<Vec<String>>,
    ha: Option<Vec<String>>,
    br: Option<Vec<String>>,
    bc: Option<Vec<String>>,
    tc: Option<Vec<String>>,
    path: Option<&str>,
) -> Matchers {
    Matchers { status, header_present: hp, header_absent: ha, body_regex: br, body_contains: bc, title_contains: tc, path: path.map(|s| s.to_string()) }
}

/// Returns all built-in vulnerability checks.
pub fn all_checks() -> Vec<Check> {
    vec![
        security_headers(), hsts_missing(), csp_missing(), cors_wildcard(), cors_credentials(),
        content_type_missing(), cache_control_missing(), referrer_policy_missing(),
        permissions_policy_missing(), coop_missing(), xss_protection_missing(),
        server_banner(), x_powered_by(), email_disclosure(), stack_trace(),
        directory_listing(), exposed_admin(), php_info(),
        git_config(), actuator_exposed(), s3_bucket(),
    ]
}

fn c(id: &str, name: &str, sev: Severity, desc: &str, matchers: Matchers) -> Check {
    Check { id: id.into(), name: name.into(), severity: sev, description: desc.into(), matchers }
}

// ── Security header checks ──

fn security_headers() -> Check {
    c("missing-security-headers", "Missing Security Headers", Severity::Medium,
      "Response missing X-Content-Type-Options or X-Frame-Options.",
      m(None, None, Some(vec!["x-content-type-options".into(), "x-frame-options".into()]), None, None, None, None))
}

fn hsts_missing() -> Check {
    c("hsts-missing", "HSTS Missing", Severity::Low,
      "Strict-Transport-Security header not set.",
      m(None, None, Some(vec!["strict-transport-security".into()]), None, None, None, None))
}

fn csp_missing() -> Check {
    c("csp-missing", "CSP Not Set", Severity::Low,
      "Content-Security-Policy header missing.",
      m(None, None, Some(vec!["content-security-policy".into()]), None, None, None, None))
}

fn cors_wildcard() -> Check {
    c("cors-wildcard", "CORS Allows All Origins", Severity::Medium,
      "Access-Control-Allow-Origin: * allows any site to read responses.",
      m(None, Some(vec!["access-control-allow-origin".into()]), None, None, None, None, None))
}

fn cors_credentials() -> Check {
    c("cors-credentials", "CORS with Credentials", Severity::Medium,
      "Access-Control-Allow-Credentials: true allows cookies with CORS.",
      m(None, Some(vec!["access-control-allow-credentials".into()]), None, None, None, None, None))
}

fn content_type_missing() -> Check {
    c("content-type-missing", "Content-Type Missing", Severity::Low,
      "Response has no Content-Type header.",
      m(None, None, Some(vec!["content-type".into()]), None, None, None, None))
}

fn cache_control_missing() -> Check {
    c("cache-control-missing", "Cache-Control Not Set", Severity::Low,
      "Cache-Control header missing.",
      m(None, None, Some(vec!["cache-control".into()]), None, None, None, None))
}

fn referrer_policy_missing() -> Check {
    c("referrer-policy-missing", "Referrer-Policy Not Set", Severity::Info,
      "Referrer-Policy header missing.",
      m(None, None, Some(vec!["referrer-policy".into()]), None, None, None, None))
}

fn permissions_policy_missing() -> Check {
    c("permissions-policy-missing", "Permissions-Policy Not Set", Severity::Info,
      "Permissions-Policy header missing.",
      m(None, None, Some(vec!["permissions-policy".into(), "feature-policy".into()]), None, None, None, None))
}

fn coop_missing() -> Check {
    c("coop-missing", "Cross-Origin-Opener-Policy Missing", Severity::Info,
      "COOP header missing.",
      m(None, None, Some(vec!["cross-origin-opener-policy".into()]), None, None, None, None))
}

fn xss_protection_missing() -> Check {
    c("xss-protection-missing", "X-XSS-Protection Missing", Severity::Info,
      "X-XSS-Protection header not set.",
      m(None, None, Some(vec!["x-xss-protection".into()]), None, None, None, None))
}

// ── Information disclosure ──

fn server_banner() -> Check {
    c("server-banner", "Server Banner Exposed", Severity::Info,
      "Server header reveals software name.",
      m(None, Some(vec!["server".into()]), None, None, None, None, None))
}

fn x_powered_by() -> Check {
    c("x-powered-by", "X-Powered-By Exposed", Severity::Info,
      "X-Powered-By header leaks framework info.",
      m(None, Some(vec!["x-powered-by".into()]), None, None, None, None, None))
}

fn email_disclosure() -> Check {
    c("email-disclosure", "Email Disclosure", Severity::Low,
      "Email pattern found in response body.",
      m(None, None, None, Some(vec![r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".into()]), None, None, None))
}

fn stack_trace() -> Check {
    c("stack-trace", "Stack Trace Exposure", Severity::High,
      "Stack trace visible in response.",
      m(None, None, None, None, Some(vec!["stack trace".into(), "traceback".into(), "stacktrace".into(), "call stack".into()]), None, None))
}

// ── Content / config ──

fn directory_listing() -> Check {
    c("directory-listing", "Directory Listing", Severity::Medium,
      "Directory listing enabled.",
      m(None, None, None, None, Some(vec!["index of /".into()]), None, None))
}

fn exposed_admin() -> Check {
    c("exposed-admin", "Exposed Admin Panel", Severity::High,
      "Login/admin panel detected.",
      m(None, None, None, None, Some(vec!["admin".into(), "login".into()]), Some(vec!["admin".into(), "login".into()]), None))
}

fn php_info() -> Check {
    c("php-info-exposed", "PHP info() Exposed", Severity::High,
      "phpinfo() output detected.",
      m(None, None, None, None, Some(vec!["php version".into()]), Some(vec!["phpinfo".into()]), None))
}

// ── Path-based checks ──

fn git_config() -> Check {
    c("git-config-exposed", "Git Config Exposed", Severity::High,
      ".git/config file is accessible.",
      m(Some(vec![200]), None, None, None, Some(vec!["repositoryformatversion".into(), "ref:".into()]), None, Some("/.git/config")))
}

fn actuator_exposed() -> Check {
    c("actuator-exposed", "Spring Actuator Exposed", Severity::High,
      "Spring Boot actuator endpoint accessible without auth.",
      m(Some(vec![200, 401, 403]), None, None, None, Some(vec!["_links".into()]), None, Some("/actuator")))
}

fn s3_bucket() -> Check {
    c("s3-bucket-listing", "S3 Bucket Listing", Severity::High,
      "S3 bucket listing is enabled.",
      m(Some(vec![200]), None, None, None, Some(vec!["<listbucketresult".into(), "<contents>".into(), "key".into()]), None, Some("/")))
}
