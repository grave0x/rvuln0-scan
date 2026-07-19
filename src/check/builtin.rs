use crate::types::{Check, Matchers, Severity};

/// Returns built-in vulnerability checks.
pub fn all_checks() -> Vec<Check> {
    vec![
        /* Security header checks */
        missing_security_headers(),
        hsts_missing(),
        csp_missing(),
        xss_protection_missing(),
        content_type_sniffing(),
        referrer_policy_missing(),
        permissions_policy_missing(),
        cors_policy(),
        coop_missing(),
        /* Information disclosure */
        server_banner(),
        x_powered_by(),
        email_disclosure(),
        stack_trace_exposure(),
        /* Content / config */
        directory_listing(),
        exposed_admin_panel(),
        php_info(),
        /* Cache / privacy */
        cache_control_missing(),
    ]
}

// ── Security header checks ──────────────────────────────────────

fn missing_security_headers() -> Check {
    Check {
        id: "missing-security-headers".into(),
        name: "Missing Security Headers".into(),
        severity: Severity::Medium,
        description: "Response missing X-Content-Type-Options or X-Frame-Options.".into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: Some(vec![
                "x-content-type-options".into(),
                "x-frame-options".into(),
            ]),
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

fn hsts_missing() -> Check {
    Check {
        id: "hsts-missing".into(),
        name: "HSTS Missing".into(),
        severity: Severity::Low,
        description: "Strict-Transport-Security header not set. HTTPS sites should set HSTS to prevent SSL stripping.".into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: Some(vec!["strict-transport-security".into()]),
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

fn csp_missing() -> Check {
    Check {
        id: "csp-missing".into(),
        name: "CSP Not Set".into(),
        severity: Severity::Low,
        description: "Content-Security-Policy header missing — increases XSS risk.".into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: Some(vec!["content-security-policy".into()]),
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

fn xss_protection_missing() -> Check {
    Check {
        id: "xss-protection-missing".into(),
        name: "X-XSS-Protection Missing".into(),
        severity: Severity::Info,
        description: "X-XSS-Protection header not set.".into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: Some(vec!["x-xss-protection".into()]),
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

fn content_type_sniffing() -> Check {
    Check {
        id: "content-type-sniffing".into(),
        name: "MIME Sniffing Not Prevented".into(),
        severity: Severity::Low,
        description: "X-Content-Type-Options: nosniff missing — browser may sniff MIME types."
            .into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: Some(vec!["x-content-type-options".into()]),
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

fn referrer_policy_missing() -> Check {
    Check {
        id: "referrer-policy-missing".into(),
        name: "Referrer-Policy Not Set".into(),
        severity: Severity::Info,
        description: "Referrer-Policy header missing — referrer info leaked on navigation.".into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: Some(vec!["referrer-policy".into()]),
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

fn permissions_policy_missing() -> Check {
    Check {
        id: "permissions-policy-missing".into(),
        name: "Permissions-Policy Not Set".into(),
        severity: Severity::Info,
        description:
            "Permissions-Policy (Feature-Policy) header missing — browser features unrestricted."
                .into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: Some(vec!["permissions-policy".into(), "feature-policy".into()]),
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

fn cors_policy() -> Check {
    Check {
        id: "cors-wildcard".into(),
        name: "CORS Allows All Origins".into(),
        severity: Severity::Medium,
        description: "Access-Control-Allow-Origin: * allows any site to read responses.".into(),
        matchers: Matchers {
            status: None,
            header_present: Some(vec!["access-control-allow-origin".into()]),
            header_absent: None,
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

fn coop_missing() -> Check {
    Check {
        id: "coop-missing".into(),
        name: "Cross-Origin-Opener-Policy Missing".into(),
        severity: Severity::Info,
        description: "COOP header missing — cross-origin popups can access window references."
            .into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: Some(vec!["cross-origin-opener-policy".into()]),
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

// ── Information disclosure ──────────────────────────────────────

fn server_banner() -> Check {
    Check {
        id: "server-banner".into(),
        name: "Server Banner Exposed".into(),
        severity: Severity::Info,
        description: "Server header reveals software name/version.".into(),
        matchers: Matchers {
            status: None,
            header_present: Some(vec!["server".into()]),
            header_absent: None,
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

fn x_powered_by() -> Check {
    Check {
        id: "x-powered-by".into(),
        name: "X-Powered-By Exposed".into(),
        severity: Severity::Info,
        description: "X-Powered-By header leaks framework/technology info.".into(),
        matchers: Matchers {
            status: None,
            header_present: Some(vec!["x-powered-by".into()]),
            header_absent: None,
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

fn email_disclosure() -> Check {
    Check {
        id: "email-disclosure".into(),
        name: "Email Address Disclosure".into(),
        severity: Severity::Low,
        description: "Email address pattern found in response body.".into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: None,
            body_regex: Some(vec![
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".into()
            ]),
            body_contains: None,
            title_contains: None,
        },
    }
}

fn stack_trace_exposure() -> Check {
    Check {
        id: "stack-trace".into(),
        name: "Stack Trace Exposure".into(),
        severity: Severity::High,
        description: "Stack trace or exception details visible in response.".into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: None,
            body_regex: None,
            body_contains: Some(vec![
                "stack trace".into(),
                "exception stack".into(),
                "at ".into(),
                "in <module>".into(),
                "file \"".into(),
            ]),
            title_contains: None,
        },
    }
}

// ── Content / config ────────────────────────────────────────────

fn directory_listing() -> Check {
    Check {
        id: "directory-listing".into(),
        name: "Directory Listing".into(),
        severity: Severity::Medium,
        description: "Directory listing may be enabled (Index of / pattern).".into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: None,
            body_regex: None,
            body_contains: Some(vec!["index of /".into()]),
            title_contains: None,
        },
    }
}

fn exposed_admin_panel() -> Check {
    Check {
        id: "exposed-admin".into(),
        name: "Exposed Admin Panel".into(),
        severity: Severity::High,
        description: "Login/admin panel detected via body or title keywords.".into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: None,
            body_regex: None,
            body_contains: Some(vec!["admin".into(), "login".into()]),
            title_contains: Some(vec!["admin".into(), "login".into()]),
        },
    }
}

fn php_info() -> Check {
    Check {
        id: "php-info-exposed".into(),
        name: "PHP info() Exposed".into(),
        severity: Severity::High,
        description: "PHP phpinfo() output detected — leaks server configuration.".into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: None,
            body_regex: None,
            body_contains: Some(vec![
                "php version".into(),
                "php license".into(),
                "php authors".into(),
                "system info".into(),
            ]),
            title_contains: Some(vec!["phpinfo".into()]),
        },
    }
}

fn cache_control_missing() -> Check {
    Check {
        id: "cache-control-missing".into(),
        name: "Cache-Control Not Set".into(),
        severity: Severity::Low,
        description: "Cache-Control header missing — sensitive content may be cached.".into(),
        matchers: Matchers {
            status: None,
            header_present: None,
            header_absent: Some(vec!["cache-control".into()]),
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}
