use crate::types::ProbeResult;

/// Technology fingerprint database.
/// Each entry: name, header key to match, header value substring (or "*"), body keyword.
struct TechFingerprint {
    name: &'static str,
    category: &'static str,
    header_key: Option<&'static str>,
    header_val: Option<&'static str>,
    body_keyword: Option<&'static str>,
}

const FINGERPRINTS: &[TechFingerprint] = &[
    TechFingerprint { name: "nginx", category: "web-server", header_key: Some("server"), header_val: Some("nginx"), body_keyword: None },
    TechFingerprint { name: "Apache", category: "web-server", header_key: Some("server"), header_val: Some("apache"), body_keyword: None },
    TechFingerprint { name: "Cloudflare", category: "cdn", header_key: Some("server"), header_val: Some("cloudflare"), body_keyword: None },
    TechFingerprint { name: "WordPress", category: "cms", header_key: None, header_val: None, body_keyword: Some("/wp-content/") },
    TechFingerprint { name: "WordPress", category: "cms", header_key: None, header_val: None, body_keyword: Some("/wp-includes/") },
    TechFingerprint { name: "Laravel", category: "framework", header_key: None, header_val: None, body_keyword: Some("laravel") },
    TechFingerprint { name: "React", category: "js-framework", header_key: None, header_val: None, body_keyword: Some("__react") },
    TechFingerprint { name: "Next.js", category: "js-framework", header_key: Some("x-powered-by"), header_val: Some("next"), body_keyword: None },
    TechFingerprint { name: "Express", category: "js-framework", header_key: Some("x-powered-by"), header_val: Some("express"), body_keyword: None },
    TechFingerprint { name: "Python", category: "language", header_key: Some("server"), header_val: Some("python"), body_keyword: None },
    TechFingerprint { name: "ASP.NET", category: "framework", header_key: Some("server"), header_val: Some("asp.net"), body_keyword: None },
    TechFingerprint { name: "IIS", category: "web-server", header_key: Some("server"), header_val: Some("iis"), body_keyword: None },
    TechFingerprint { name: "GitHub Pages", category: "hosting", header_key: None, header_val: None, body_keyword: Some("github.com") },
    TechFingerprint { name: "Pinterest", category: "social", header_key: None, header_val: None, body_keyword: Some("pinterest") },
    TechFingerprint { name: "Joomla", category: "cms", header_key: None, header_val: None, body_keyword: Some("/components/") },
    TechFingerprint { name: "Drupal", category: "cms", header_key: None, header_val: None, body_keyword: Some("drupal") },
    TechFingerprint { name: "Shopify", category: "ecommerce", header_key: Some("x-shopify-stage"), header_val: Some("*"), body_keyword: None },
    TechFingerprint { name: "Vue.js", category: "js-framework", header_key: None, header_val: None, body_keyword: Some("__vue_") },
    TechFingerprint { name: "Tomcat", category: "web-server", header_key: Some("server"), header_val: Some("tomcat"), body_keyword: None },
    TechFingerprint { name: "Jetty", category: "web-server", header_key: Some("server"), header_val: Some("jetty"), body_keyword: None },
];

/// Detect technologies from a probe result.
pub fn detect_tech(result: &ProbeResult) -> Vec<String> {
    let mut detected: Vec<String> = Vec::new();
    let body_lower = result.body_preview.to_lowercase();

    for fp in FINGERPRINTS {
        let mut matched = false;

        if let Some(k) = fp.header_key {
            if let Some(val) = result.headers.get(k) {
                let val_lower = val.to_lowercase();
                match fp.header_val {
                    Some("*") => matched = true,
                    Some(v) if val_lower.contains(v) => matched = true,
                    _ => {}
                }
            }
        }

        if !matched && fp.header_key.is_none() || matched {
            // also check body keyword if specified
            if let Some(kw) = fp.body_keyword {
                if body_lower.contains(kw) {
                    matched = true;
                } else if fp.header_key.is_some() {
                    // if header already matched, body keyword is additional
                } else {
                    matched = false;
                }
            }
        }

        if matched && !detected.contains(&fp.name.to_string()) {
            detected.push(fp.name.to_string());
        }
    }

    detected
}
