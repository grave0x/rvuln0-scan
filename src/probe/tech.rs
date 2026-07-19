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
    // Web servers
    TechFingerprint { name: "nginx", category: "web-server", header_key: Some("server"), header_val: Some("nginx"), body_keyword: None },
    TechFingerprint { name: "Apache", category: "web-server", header_key: Some("server"), header_val: Some("apache"), body_keyword: None },
    TechFingerprint { name: "IIS", category: "web-server", header_key: Some("server"), header_val: Some("iis"), body_keyword: None },
    TechFingerprint { name: "Tomcat", category: "web-server", header_key: Some("server"), header_val: Some("tomcat"), body_keyword: None },
    TechFingerprint { name: "Jetty", category: "web-server", header_key: Some("server"), header_val: Some("jetty"), body_keyword: None },
    TechFingerprint { name: "Caddy", category: "web-server", header_key: Some("server"), header_val: Some("caddy"), body_keyword: None },
    TechFingerprint { name: "Lighttpd", category: "web-server", header_key: Some("server"), header_val: Some("lighttpd"), body_keyword: None },
    TechFingerprint { name: "OpenResty", category: "web-server", header_key: Some("server"), header_val: Some("openresty"), body_keyword: None },

    // CDN / reverse proxy
    TechFingerprint { name: "Cloudflare", category: "cdn", header_key: Some("server"), header_val: Some("cloudflare"), body_keyword: None },
    TechFingerprint { name: "Akamai", category: "cdn", header_key: Some("server"), header_val: Some("akamai"), body_keyword: None },
    TechFingerprint { name: "Fastly", category: "cdn", header_key: Some("server"), header_val: Some("fastly"), body_keyword: None },
    TechFingerprint { name: "CloudFront", category: "cdn", header_key: Some("server"), header_val: Some("cloudfront"), body_keyword: None },
    TechFingerprint { name: "Varnish", category: "cdn", header_key: Some("server"), header_val: Some("varnish"), body_keyword: None },
    TechFingerprint { name: "Incapsula", category: "cdn", header_key: Some("server"), header_val: Some("incapsula"), body_keyword: None },
    TechFingerprint { name: "Sucuri", category: "cdn", header_key: Some("server"), header_val: Some("sucuri"), body_keyword: None },

    // CMS
    TechFingerprint { name: "WordPress", category: "cms", header_key: None, header_val: None, body_keyword: Some("/wp-content/") },
    TechFingerprint { name: "WordPress", category: "cms", header_key: None, header_val: None, body_keyword: Some("/wp-includes/") },
    TechFingerprint { name: "WordPress", category: "cms", header_key: None, header_val: None, body_keyword: Some("wp-json") },
    TechFingerprint { name: "Drupal", category: "cms", header_key: None, header_val: None, body_keyword: Some("drupal") },
    TechFingerprint { name: "Joomla", category: "cms", header_key: None, header_val: None, body_keyword: Some("/components/") },
    TechFingerprint { name: "Joomla", category: "cms", header_key: None, header_val: None, body_keyword: Some("/modules/") },
    TechFingerprint { name: "Magento", category: "cms", header_key: None, header_val: None, body_keyword: Some("mage/") },
    TechFingerprint { name: "Magento", category: "cms", header_key: None, header_val: None, body_keyword: Some("Magento") },
    TechFingerprint { name: "Shopify", category: "ecommerce", header_key: Some("x-shopify-stage"), header_val: Some("*"), body_keyword: None },
    TechFingerprint { name: "Shopify", category: "ecommerce", header_key: None, header_val: None, body_keyword: Some("myshopify.com") },
    TechFingerprint { name: "Wix", category: "cms", header_key: None, header_val: None, body_keyword: Some("wix.com") },
    TechFingerprint { name: "Squarespace", category: "cms", header_key: None, header_val: None, body_keyword: Some("squarespace.com") },
    TechFingerprint { name: "Webflow", category: "cms", header_key: Some("server"), header_val: Some("webflow"), body_keyword: None },
    TechFingerprint { name: "Ghost", category: "cms", header_key: None, header_val: None, body_keyword: Some("ghost") },
    TechFingerprint { name: "Umbraco", category: "cms", header_key: None, header_val: None, body_keyword: Some("umbraco") },

    // JavaScript frameworks
    TechFingerprint { name: "React", category: "js-framework", header_key: None, header_val: None, body_keyword: Some("__react") },
    TechFingerprint { name: "React", category: "js-framework", header_key: None, header_val: None, body_keyword: Some("reactroot") },
    TechFingerprint { name: "Next.js", category: "js-framework", header_key: Some("x-powered-by"), header_val: Some("next"), body_keyword: None },
    TechFingerprint { name: "Vue.js", category: "js-framework", header_key: None, header_val: None, body_keyword: Some("__vue_") },
    TechFingerprint { name: "Angular", category: "js-framework", header_key: None, header_val: None, body_keyword: Some("ng-version") },
    TechFingerprint { name: "Angular", category: "js-framework", header_key: None, header_val: None, body_keyword: Some("ng-app") },
    TechFingerprint { name: "Svelte", category: "js-framework", header_key: None, header_val: None, body_keyword: Some("svelte-") },
    TechFingerprint { name: "Nuxt.js", category: "js-framework", header_key: None, header_val: None, body_keyword: Some("__nuxt") },
    TechFingerprint { name: "Gatsby", category: "js-framework", header_key: None, header_val: None, body_keyword: Some("gatsby-") },
    TechFingerprint { name: "Alpine.js", category: "js-framework", header_key: None, header_val: None, body_keyword: Some("x-data") },

    // Backend frameworks
    TechFingerprint { name: "Express", category: "framework", header_key: Some("x-powered-by"), header_val: Some("express"), body_keyword: None },
    TechFingerprint { name: "Laravel", category: "framework", header_key: None, header_val: None, body_keyword: Some("laravel") },
    TechFingerprint { name: "Rails", category: "framework", header_key: Some("server"), header_val: Some("passenger"), body_keyword: None },
    TechFingerprint { name: "Rails", category: "framework", header_key: Some("x-powered-by"), header_val: Some("phusion"), body_keyword: None },
    TechFingerprint { name: "Django", category: "framework", header_key: Some("server"), header_val: Some("wsgi"), body_keyword: None },
    TechFingerprint { name: "Flask", category: "framework", header_key: None, header_val: None, body_keyword: Some("flask") },
    TechFingerprint { name: "Spring", category: "framework", header_key: Some("x-application-context"), header_val: Some("*"), body_keyword: None },
    TechFingerprint { name: "ASP.NET", category: "framework", header_key: Some("server"), header_val: Some("asp.net"), body_keyword: None },
    TechFingerprint { name: "FastAPI", category: "framework", header_key: Some("server"), header_val: Some("uvicorn"), body_keyword: None },
    TechFingerprint { name: "Koa", category: "framework", header_key: None, header_val: None, body_keyword: Some("koa") },

    // Languages
    TechFingerprint { name: "Python", category: "language", header_key: Some("server"), header_val: Some("python"), body_keyword: None },
    TechFingerprint { name: "PHP", category: "language", header_key: None, header_val: None, body_keyword: Some("php") },
    TechFingerprint { name: "Ruby", category: "language", header_key: None, header_val: None, body_keyword: Some("ruby") },
    TechFingerprint { name: "Java", category: "language", header_key: None, header_val: None, body_keyword: Some("java") },
    TechFingerprint { name: "Go", category: "language", header_key: Some("server"), header_val: Some("golang"), body_keyword: None },

    // Analytics / marketing
    TechFingerprint { name: "Google Analytics", category: "analytics", header_key: None, header_val: None, body_keyword: Some("ga.js") },
    TechFingerprint { name: "Google Analytics 4", category: "analytics", header_key: None, header_val: None, body_keyword: Some("gtag") },
    TechFingerprint { name: "Google Tag Manager", category: "analytics", header_key: None, header_val: None, body_keyword: Some("gtm.js") },
    TechFingerprint { name: "Facebook Pixel", category: "analytics", header_key: None, header_val: None, body_keyword: Some("fbq(") },
    TechFingerprint { name: "Hotjar", category: "analytics", header_key: None, header_val: None, body_keyword: Some("hotjar") },
    TechFingerprint { name: "HubSpot", category: "analytics", header_key: None, header_val: None, body_keyword: Some("hubspot") },
    TechFingerprint { name: "Mixpanel", category: "analytics", header_key: None, header_val: None, body_keyword: Some("mixpanel") },
    TechFingerprint { name: "Intercom", category: "analytics", header_key: None, header_val: None, body_keyword: Some("intercom") },

    // Cloud / hosting
    TechFingerprint { name: "GitHub Pages", category: "hosting", header_key: None, header_val: None, body_keyword: Some("github.com") },
    TechFingerprint { name: "Netlify", category: "hosting", header_key: Some("server"), header_val: Some("netlify"), body_keyword: None },
    TechFingerprint { name: "Vercel", category: "hosting", header_key: Some("server"), header_val: Some("vercel"), body_keyword: None },
    TechFingerprint { name: "Heroku", category: "hosting", header_key: None, header_val: None, body_keyword: Some("heroku") },
    TechFingerprint { name: "AWS", category: "hosting", header_key: None, header_val: None, body_keyword: Some("aws") },

    // Misc
    TechFingerprint { name: "jQuery", category: "library", header_key: None, header_val: None, body_keyword: Some("jquery") },
    TechFingerprint { name: "Bootstrap", category: "library", header_key: None, header_val: None, body_keyword: Some("bootstrap") },
    TechFingerprint { name: "Tailwind CSS", category: "library", header_key: None, header_val: None, body_keyword: Some("tailwindcss") },
    TechFingerprint { name: "Font Awesome", category: "library", header_key: None, header_val: None, body_keyword: Some("font-awesome") },
    TechFingerprint { name: "Google Fonts", category: "library", header_key: None, header_val: None, body_keyword: Some("fonts.googleapis") },
    TechFingerprint { name: "reCAPTCHA", category: "security", header_key: None, header_val: None, body_keyword: Some("recaptcha") },
    TechFingerprint { name: "Cloudflare Bot Management", category: "security", header_key: None, header_val: None, body_keyword: Some("cf-bm") },
];

/// Detect technologies from a probe result.
pub fn detect_tech(result: &crate::types::ProbeResult) -> Vec<String> {
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

        if matched && !detected.contains(&fp.name.to_string()) {
            detected.push(fp.name.to_string());
        }
    }

    detected
}
