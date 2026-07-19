use crate::types::{Check, Matchers, Severity};

/// Returns built-in vulnerability checks.
pub fn all_checks() -> Vec<Check> {
    vec![
        missing_security_headers(),
        info_disclosure(),
        open_cors(),
        directory_listing(),
        exposed_admin_panel(),
    ]
}

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

fn info_disclosure() -> Check {
    Check {
        id: "info-disclosure".into(),
        name: "Information Disclosure".into(),
        severity: Severity::Info,
        description: "Server banner or version info exposed.".into(),
        matchers: Matchers {
            status: None,
            header_present: Some(vec!["server".into(), "x-powered-by".into()]),
            header_absent: None,
            body_regex: None,
            body_contains: None,
            title_contains: None,
        },
    }
}

fn open_cors() -> Check {
    Check {
        id: "open-cors".into(),
        name: "Permissive CORS".into(),
        severity: Severity::Medium,
        description: "CORS allows all origins (*).".into(),
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

fn directory_listing() -> Check {
    Check {
        id: "directory-listing".into(),
        name: "Directory Listing".into(),
        severity: Severity::Medium,
        description: "Directory listing may be enabled.".into(),
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
        description: "Login/admin panel detected.".into(),
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
