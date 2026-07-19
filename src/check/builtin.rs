use crate::types::{Check, Severity, Matchers};

fn m(status: Option<Vec<u16>>, hp: Option<Vec<String>>, ha: Option<Vec<String>>, br: Option<Vec<String>>, bc: Option<Vec<String>>, tc: Option<Vec<String>>, path: Option<&str>) -> Matchers {
    Matchers { status, header_present: hp, header_absent: ha, body_regex: br, body_contains: bc, title_contains: tc, path: path.map(|s| s.to_string()) }
}

fn c(id: &str, name: &str, sev: Severity, desc: &str, matchers: Matchers) -> Check {
    Check { id: id.into(), name: name.into(), severity: sev, description: desc.into(), matchers }
}

fn pc(id: &str, name: &str, sev: Severity, desc: &str, path: &str, status: Option<Vec<u16>>, bc: Option<Vec<String>>) -> Check {
    c(id, name, sev, desc, m(status, None, None, None, bc, None, Some(path)))
}

pub fn all_checks() -> Vec<Check> {
    vec![
        // Header-based checks
        security_headers(), hsts_missing(), csp_missing(), cors_wildcard(), cors_credentials(),
        content_type_missing(), cache_control_missing(), referrer_policy_missing(),
        permissions_policy_missing(), coop_missing(), xss_protection_missing(),
        server_banner(), x_powered_by(), email_disclosure(), stack_trace(),
        directory_listing(), exposed_admin(), php_info(),
        // Path-based checks
        git_config(), git_head(), svn_entries(), env_file(), wp_admin(), wp_login(),
        actuator(), actuator_health(), actuator_env(), h2_console(), swagger_ui(),
        web_inf(), crossdomain(), sitemap(), robots_txt(), security_txt(),
        server_status(), debug_page(), phpinfo_page(), laravel_env(),
        gemfile(), composer_json(), package_json(),
        // S3
        s3_bucket(),
    ]
}

// ── Security header checks ──

fn security_headers() -> Check {
    c("missing-security-headers", "Missing Security Headers", Severity::Medium,
      "Response missing X-Content-Type-Options or X-Frame-Options.",
      m(None, None, Some(vec!["x-content-type-options".into(), "x-frame-options".into()]), None, None, None, None))
}
fn hsts_missing() -> Check { c("hsts-missing", "HSTS Missing", Severity::Low, "Strict-Transport-Security header not set.", m(None, None, Some(vec!["strict-transport-security".into()]), None, None, None, None)) }
fn csp_missing() -> Check { c("csp-missing", "CSP Not Set", Severity::Low, "Content-Security-Policy header missing.", m(None, None, Some(vec!["content-security-policy".into()]), None, None, None, None)) }
fn cors_wildcard() -> Check { c("cors-wildcard", "CORS Allows All Origins", Severity::Medium, "Access-Control-Allow-Origin: *.", m(None, Some(vec!["access-control-allow-origin".into()]), None, None, None, None, None)) }
fn cors_credentials() -> Check { c("cors-credentials", "CORS with Credentials", Severity::Medium, "Access-Control-Allow-Credentials: true.", m(None, Some(vec!["access-control-allow-credentials".into()]), None, None, None, None, None)) }
fn content_type_missing() -> Check { c("content-type-missing", "Content-Type Missing", Severity::Low, "No Content-Type header.", m(None, None, Some(vec!["content-type".into()]), None, None, None, None)) }
fn cache_control_missing() -> Check { c("cache-control-missing", "Cache-Control Not Set", Severity::Low, "Cache-Control header missing.", m(None, None, Some(vec!["cache-control".into()]), None, None, None, None)) }
fn referrer_policy_missing() -> Check { c("referrer-policy-missing", "Referrer-Policy Not Set", Severity::Info, "Referrer-Policy header missing.", m(None, None, Some(vec!["referrer-policy".into()]), None, None, None, None)) }
fn permissions_policy_missing() -> Check { c("permissions-policy-missing", "Permissions-Policy Not Set", Severity::Info, "Permissions-Policy header missing.", m(None, None, Some(vec!["permissions-policy".into(), "feature-policy".into()]), None, None, None, None)) }
fn coop_missing() -> Check { c("coop-missing", "Cross-Origin-Opener-Policy Missing", Severity::Info, "COOP header missing.", m(None, None, Some(vec!["cross-origin-opener-policy".into()]), None, None, None, None)) }
fn xss_protection_missing() -> Check { c("xss-protection-missing", "X-XSS-Protection Missing", Severity::Info, "X-XSS-Protection not set.", m(None, None, Some(vec!["x-xss-protection".into()]), None, None, None, None)) }

// ── Information disclosure ──

fn server_banner() -> Check { c("server-banner", "Server Banner Exposed", Severity::Info, "Server header reveals software name.", m(None, Some(vec!["server".into()]), None, None, None, None, None)) }
fn x_powered_by() -> Check { c("x-powered-by", "X-Powered-By Exposed", Severity::Info, "X-Powered-By header leaks framework.", m(None, Some(vec!["x-powered-by".into()]), None, None, None, None, None)) }
fn email_disclosure() -> Check { c("email-disclosure", "Email Disclosure", Severity::Low, "Email pattern found in body.", m(None, None, None, Some(vec![r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".into()]), None, None, None)) }
fn stack_trace() -> Check { c("stack-trace", "Stack Trace Exposure", Severity::High, "Stack trace visible in response.", m(None, None, None, None, Some(vec!["stack trace".into(), "traceback".into(), "stacktrace".into(), "call stack".into()]), None, None)) }

// ── Content-based ──

fn directory_listing() -> Check { c("directory-listing", "Directory Listing", Severity::Medium, "Directory listing enabled.", m(None, None, None, None, Some(vec!["index of /".into()]), None, None)) }
fn exposed_admin() -> Check { c("exposed-admin", "Exposed Admin Panel", Severity::High, "Login/admin panel detected.", m(None, None, None, None, Some(vec!["admin".into(), "login".into()]), Some(vec!["admin".into(), "login".into()]), None)) }
fn php_info() -> Check { c("php-info-exposed", "PHP info() Exposed", Severity::High, "phpinfo() output detected.", m(None, None, None, None, Some(vec!["php version".into()]), Some(vec!["phpinfo".into()]), None)) }

// ── Path-based checks ──

fn git_config() -> Check { pc("git-config-exposed", "Git Config Exposed", Severity::High, ".git/config is accessible.", "/.git/config", Some(vec![200]), Some(vec!["repositoryformatversion".into(), "ref:".into()])) }
fn git_head() -> Check { pc("git-head-exposed", "Git HEAD Exposed", Severity::High, ".git/HEAD is accessible.", "/.git/HEAD", Some(vec![200]), Some(vec!["ref:".into()])) }
fn svn_entries() -> Check { pc("svn-entries-exposed", "SVN Entries Exposed", Severity::High, ".svn/entries is accessible.", "/.svn/entries", Some(vec![200]), Some(vec!["svn".into()])) }
fn env_file() -> Check { pc("env-exposed", "Environment File Exposed", Severity::High, ".env file is accessible.", "/.env", Some(vec![200]), Some(vec!["APP_KEY".into(), "DB_HOST".into(), "SECRET".into()])) }
fn wp_admin() -> Check { pc("wp-admin-exposed", "WordPress Admin Exposed", Severity::Medium, "WordPress admin panel is accessible.", "/wp-admin/", Some(vec![200, 302]), None) }
fn wp_login() -> Check { pc("wp-login-exposed", "WordPress Login Exposed", Severity::Medium, "WordPress login page is accessible.", "/wp-login.php", Some(vec![200]), Some(vec!["wp-login".into(), "wordpress".into()])) }
fn actuator() -> Check { pc("actuator-exposed", "Spring Actuator Exposed", Severity::High, "Actuator endpoint accessible.", "/actuator", Some(vec![200, 401, 403]), Some(vec!["_links".into()])) }
fn actuator_health() -> Check { pc("actuator-health", "Actuator Health Exposed", Severity::Medium, "Actuator health endpoint.", "/actuator/health", Some(vec![200]), Some(vec!["status".into(), "UP".into()])) }
fn actuator_env() -> Check { pc("actuator-env", "Actuator Env Exposed", Severity::High, "Actuator env endpoint.", "/actuator/env", Some(vec![200, 401, 403]), Some(vec!["java".into(), "os".into(), "path".into()])) }
fn h2_console() -> Check { pc("h2-console-exposed", "H2 Console Exposed", Severity::High, "H2 database console accessible.", "/h2-console", Some(vec![200, 302]), Some(vec!["h2".into(), "database".into()])) }
fn swagger_ui() -> Check { pc("swagger-ui-exposed", "Swagger UI Exposed", Severity::Medium, "Swagger UI accessible.", "/swagger-ui.html", Some(vec![200]), Some(vec!["swagger".into(), "api".into()])) }
fn web_inf() -> Check { pc("web-inf-exposed", "WEB-INF Exposed", Severity::High, "WEB-INF/web.xml accessible.", "/WEB-INF/web.xml", Some(vec![200]), Some(vec!["web-app".into(), "servlet".into()])) }
fn crossdomain() -> Check { pc("crossdomain-exposed", "Crossdomain XML", Severity::Low, "Flash crossdomain.xml policy file.", "/crossdomain.xml", Some(vec![200]), Some(vec!["cross-domain-policy".into()])) }
fn sitemap() -> Check { pc("sitemap-found", "Sitemap Found", Severity::Info, "Sitemap.xml is accessible.", "/sitemap.xml", Some(vec![200]), Some(vec!["urlset".into(), "url".into()])) }
fn robots_txt() -> Check { pc("robots-found", "Robots.txt Found", Severity::Info, "Robots.txt is accessible.", "/robots.txt", Some(vec![200]), Some(vec!["disallow".into(), "allow".into(), "sitemap".into()])) }
fn security_txt() -> Check { pc("security-txt-found", "Security.txt Found", Severity::Info, "Security.txt is accessible.", "/.well-known/security.txt", Some(vec![200]), Some(vec!["contact".into(), "mailto".into()])) }
fn server_status() -> Check { pc("server-status-exposed", "Apache Server Status", Severity::Medium, "Apache server-status accessible.", "/server-status", Some(vec![200]), Some(vec!["server version".into(), "apache".into()])) }
fn debug_page() -> Check { pc("debug-page-exposed", "Debug Page Exposed", Severity::Medium, "Debug page accessible.", "/debug", Some(vec![200]), Some(vec!["debug".into(), "trace".into()])) }
fn phpinfo_page() -> Check { pc("phpinfo-page", "PHP Info Page", Severity::High, "phpinfo.php accessible.", "/phpinfo.php", Some(vec![200]), Some(vec!["php version".into(), "php license".into()])) }
fn laravel_env() -> Check { pc("laravel-env-exposed", "Laravel .env Exposed", Severity::High, "Laravel .env accessible.", "/laravel/.env", Some(vec![200]), Some(vec!["laravel".into(), "APP_KEY".into()])) }
fn gemfile() -> Check { pc("gemfile-exposed", "Gemfile Exposed", Severity::Low, "Gemfile is accessible.", "/Gemfile", Some(vec![200]), Some(vec!["gem".into(), "ruby".into()])) }
fn composer_json() -> Check { pc("composer-exposed", "composer.json Exposed", Severity::Low, "composer.json is accessible.", "/composer.json", Some(vec![200]), Some(vec!["require".into(), "autoload".into()])) }
fn package_json() -> Check { pc("package-exposed", "package.json Exposed", Severity::Low, "package.json is accessible.", "/package.json", Some(vec![200]), Some(vec!["dependencies".into(), "scripts".into()])) }
fn s3_bucket() -> Check { pc("s3-bucket-listing", "S3 Bucket Listing", Severity::High, "S3 bucket listing enabled.", "/", Some(vec![200]), Some(vec!["listbucketresult".into(), "contents".into(), "key".into()])) }
