use crate::types::ProbeResult;

/// Technology fingerprint database.
/// Each entry: name, header key to match, header value substring (or "*"), body keyword.
#[allow(dead_code)]
struct TechFingerprint {
    name: &'static str,
    category: &'static str,
    header_key: Option<&'static str>,
    header_val: Option<&'static str>,
    body_keyword: Option<&'static str>,
}

const FINGERPRINTS: &[TechFingerprint] = &[
    TechFingerprint {
        name: "nginx",
        category: "web-server",
        header_key: Some("server"),
        header_val: Some("nginx"),
        body_keyword: None,
    },
    TechFingerprint {
        name: "Apache",
        category: "web-server",
        header_key: Some("server"),
        header_val: Some("apache"),
        body_keyword: None,
    },
    TechFingerprint {
        name: "Cloudflare",
        category: "cdn",
        header_key: Some("server"),
        header_val: Some("cloudflare"),
        body_keyword: None,
    },
    TechFingerprint {
        name: "WordPress",
        category: "cms",
        header_key: None,
        header_val: None,
        body_keyword: Some("/wp-content/"),
    },
    TechFingerprint {
        name: "WordPress",
        category: "cms",
        header_key: None,
        header_val: None,
        body_keyword: Some("/wp-includes/"),
    },
    TechFingerprint {
        name: "Laravel",
        category: "framework",
        header_key: None,
        header_val: None,
        body_keyword: Some("laravel"),
    },
    TechFingerprint {
        name: "React",
        category: "js-framework",
        header_key: None,
        header_val: None,
        body_keyword: Some("__react"),
    },
    TechFingerprint {
        name: "Next.js",
        category: "js-framework",
        header_key: Some("x-powered-by"),
        header_val: Some("next"),
        body_keyword: None,
    },
    TechFingerprint {
        name: "Express",
        category: "js-framework",
        header_key: Some("x-powered-by"),
        header_val: Some("express"),
        body_keyword: None,
    },
    TechFingerprint {
        name: "Python",
        category: "language",
        header_key: Some("server"),
        header_val: Some("python"),
        body_keyword: None,
    },
    TechFingerprint {
        name: "ASP.NET",
        category: "framework",
        header_key: Some("server"),
        header_val: Some("asp.net"),
        body_keyword: None,
    },
    TechFingerprint {
        name: "IIS",
        category: "web-server",
        header_key: Some("server"),
        header_val: Some("iis"),
        body_keyword: None,
    },
    TechFingerprint {
        name: "GitHub Pages",
        category: "hosting",
        header_key: None,
        header_val: None,
        body_keyword: Some("github.com"),
    },
    TechFingerprint {
        name: "Pinterest",
        category: "social",
        header_key: None,
        header_val: None,
        body_keyword: Some("pinterest"),
    },
    TechFingerprint {
        name: "Joomla",
        category: "cms",
        header_key: None,
        header_val: None,
        body_keyword: Some("/components/"),
    },
    TechFingerprint {
        name: "Drupal",
        category: "cms",
        header_key: None,
        header_val: None,
        body_keyword: Some("drupal"),
    },
    TechFingerprint {
        name: "Shopify",
        category: "ecommerce",
        header_key: Some("x-shopify-stage"),
        header_val: Some("*"),
        body_keyword: None,
    },
    TechFingerprint {
        name: "Vue.js",
        category: "js-framework",
        header_key: None,
        header_val: None,
        body_keyword: Some("__vue_"),
    },
    TechFingerprint {
        name: "Tomcat",
        category: "web-server",
        header_key: Some("server"),
        header_val: Some("tomcat"),
        body_keyword: None,
    },
    TechFingerprint {
        name: "Jetty",
        category: "web-server",
        header_key: Some("server"),
        header_val: Some("jetty"),
        body_keyword: None,
    },
];

/// Detect technologies from a probe result.
pub fn detect_tech(result: &ProbeResult) -> Vec<String> {
    let mut detected: Vec<String> = Vec::new();
    let body_lower = result.body_preview.to_lowercase();

    for fp in FINGERPRINTS {
        let mut matched = false;

        // Check header-based fingerprint
        if let Some(k) = fp.header_key {
            if let Some(val) = result.headers.get(k) {
                let val_lower = val.to_lowercase();
                matched = match fp.header_val {
                    Some("*") => true,
                    Some(v) => val_lower.contains(v),
                    None => true,
                };
            }
        }

        // If no header match or fingerprint has no header key, check body keyword
        if !matched && fp.header_key.is_none() || matched && fp.header_key.is_none() {
            if let Some(kw) = fp.body_keyword {
                matched = body_lower.contains(kw);
            }
        }

        // For header-only fingerprints that matched, matched stays true
        // For body-only fingerprints, matched is determined by body match above

        if matched && !detected.contains(&fp.name.to_string()) {
            detected.push(fp.name.to_string());
        }
    }

    detected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProbeResult;
    use std::time::Duration;

    fn probe_with_headers(headers: Vec<(&str, &str)>, body: &str) -> ProbeResult {
        ProbeResult {
            target: "http://test.local".into(),
            url: "http://test.local".into(),
            status_code: 200,
            headers: headers.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body_preview: body.to_string(),
            content_length: body.len(),
            response_time: Duration::from_millis(10),
            title: None,
            tech: vec![],
            tls: None,
            error: None,
        }
    }

    #[test]
    fn test_detect_nginx() {
        let p = probe_with_headers(vec![("server", "nginx/1.20.1")], "");
        let tech = detect_tech(&p);
        assert!(tech.contains(&"nginx".to_string()));
    }

    #[test]
    fn test_detect_apache() {
        let p = probe_with_headers(vec![("server", "Apache/2.4.41")], "");
        let tech = detect_tech(&p);
        assert!(tech.contains(&"Apache".to_string()));
    }

    #[test]
    fn test_detect_wordpress() {
        let p = probe_with_headers(vec![], "<html><body>/wp-content/themes/theme/style.css</body></html>");
        let tech = detect_tech(&p);
        assert!(tech.contains(&"WordPress".to_string()));
    }

    #[test]
    fn test_detect_cloudflare() {
        let p = probe_with_headers(vec![("server", "cloudflare")], "");
        let tech = detect_tech(&p);
        assert!(tech.contains(&"Cloudflare".to_string()));
    }

    #[test]
    fn test_no_false_positives() {
        let p = probe_with_headers(vec![("server", "custom-server/1.0")], "<html><body>hello world</body></html>");
        let tech = detect_tech(&p);
        // Should not detect anything from this random response
        assert!(!tech.contains(&"nginx".to_string()));
        assert!(!tech.contains(&"Apache".to_string()));
        assert!(!tech.contains(&"WordPress".to_string()));
    }

    #[test]
    fn test_multiple_tech() {
        let p = probe_with_headers(
            vec![("server", "nginx"), ("x-powered-by", "Express")],
            "<html><body>/wp-content/themes/</body></html>",
        );
        let tech = detect_tech(&p);
        assert!(tech.contains(&"nginx".to_string()));
        assert!(tech.contains(&"WordPress".to_string()));
    }
}
