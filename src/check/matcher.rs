use crate::types::{Check, Matchers, ProbeResult};
use regex::Regex;

/// Check if a probe result matches a check's matchers.
pub fn matches(check: &Check, probe: &ProbeResult) -> bool {
    let Matchers {
        status,
        header_present,
        header_absent,
        body_regex,
        body_contains,
        title_contains,
    } = &check.matchers;

    // If no matchers defined, don't match
    if status.is_none()
        && header_present.is_none()
        && header_absent.is_none()
        && body_regex.is_none()
        && body_contains.is_none()
        && title_contains.is_none()
    {
        return false;
    }

    let mut all_match = true;

    if let Some(codes) = status {
        if !codes.contains(&probe.status_code) {
            all_match = false;
        }
    }

    if let Some(present) = header_present {
        for h in present {
            if !probe.headers.contains_key(h.as_str()) {
                all_match = false;
            }
        }
    }

    if let Some(absent) = header_absent {
        for h in absent {
            if probe.headers.contains_key(h.as_str()) {
                all_match = false;
            }
        }
    }

    if let Some(patterns) = body_regex {
        for pat in patterns {
            if let Ok(re) = Regex::new(pat) {
                if !re.is_match(&probe.body_preview) {
                    all_match = false;
                }
            }
        }
    }

    if let Some(needles) = body_contains {
        let body_lower = probe.body_preview.to_lowercase();
        for n in needles {
            if !body_lower.contains(&n.to_lowercase()) {
                all_match = false;
            }
        }
    }

    if let Some(titles) = title_contains {
        if let Some(ref t) = probe.title {
            let t_lower = t.to_lowercase();
            for ti in titles {
                if !t_lower.contains(&ti.to_lowercase()) {
                    all_match = false;
                }
            }
        } else {
            all_match = false;
        }
    }

    all_match
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;
    use std::collections::HashMap;

    fn make_headers(pairs: Vec<(&str, &str)>) -> HashMap<String, String> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn probe(status: u16, headers: HashMap<String, String>, body: &str, title: Option<&str>) -> ProbeResult {
        ProbeResult {
            target: "http://test.local".into(),
            url: "http://test.local".into(),
            status_code: status,
            headers,
            body_preview: body.to_string(),
            content_length: body.len(),
            response_time: std::time::Duration::from_millis(10),
            title: title.map(|s| s.to_string()),
            tech: vec![],
            tls: None,
            error: None,
        }
    }

    #[test]
    fn test_status_matcher_positive() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers { status: Some(vec![200]), header_present: None, header_absent: None, body_regex: None, body_contains: None, title_contains: None },
        };
        let p = probe(200, HashMap::new(), "", None);
        assert!(matches(&c, &p));
    }

    #[test]
    fn test_status_matcher_negative() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers { status: Some(vec![404]), header_present: None, header_absent: None, body_regex: None, body_contains: None, title_contains: None },
        };
        let p = probe(200, HashMap::new(), "", None);
        assert!(!matches(&c, &p));
    }

    #[test]
    fn test_header_present_positive() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers { status: None, header_present: Some(vec!["server".into()]), header_absent: None, body_regex: None, body_contains: None, title_contains: None },
        };
        let p = probe(200, make_headers(vec![("server", "nginx/1.2")]), "", None);
        assert!(matches(&c, &p));
    }

    #[test]
    fn test_header_absent_positive() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers { status: None, header_present: None, header_absent: Some(vec!["x-frame-options".into()]), body_regex: None, body_contains: None, title_contains: None },
        };
        let p = probe(200, make_headers(vec![("server", "nginx")]), "", None);
        assert!(matches(&c, &p));
    }

    #[test]
    fn test_body_contains_positive() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers { status: None, header_present: None, header_absent: None, body_regex: None, body_contains: Some(vec!["admin".into()]), title_contains: None },
        };
        let p = probe(200, HashMap::new(), "<html>admin panel</html>", None);
        assert!(matches(&c, &p));
    }

    #[test]
    fn test_body_contains_case_insensitive() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers { status: None, header_present: None, header_absent: None, body_regex: None, body_contains: Some(vec!["Admin".into()]), title_contains: None },
        };
        let p = probe(200, HashMap::new(), "ADMIN PANEL", None);
        assert!(matches(&c, &p));
    }

    #[test]
    fn test_title_contains_positive() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers { status: None, header_present: None, header_absent: None, body_regex: None, body_contains: None, title_contains: Some(vec!["Dashboard".into()]) },
        };
        let p = probe(200, HashMap::new(), "", Some("Admin Dashboard"));
        assert!(matches(&c, &p));
    }

    #[test]
    fn test_title_contains_missing_title() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers { status: None, header_present: None, header_absent: None, body_regex: None, body_contains: None, title_contains: Some(vec!["Dashboard".into()]) },
        };
        let p = probe(200, HashMap::new(), "", None);
        assert!(!matches(&c, &p));
    }

    #[test]
    fn test_body_regex_positive() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers { status: None, header_present: None, header_absent: None, body_regex: Some(vec![r"(?i)php\s+version".into()]), body_contains: None, title_contains: None },
        };
        let p = probe(200, HashMap::new(), "PHP Version 8.1", None);
        assert!(matches(&c, &p));
    }

    #[test]
    fn test_and_logic_all_must_match() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers {
                status: Some(vec![200]),
                header_present: Some(vec!["server".into()]),
                header_absent: Some(vec!["x-frame-options".into()]),
                body_regex: None,
                body_contains: Some(vec!["admin".into()]),
                title_contains: Some(vec!["Admin".into()]),
            },
        };
        let p = probe(200, make_headers(vec![("server", "nginx")]), "admin panel", Some("Admin Page"));
        assert!(matches(&c, &p));
    }

    #[test]
    fn test_and_logic_one_fails() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers {
                status: Some(vec![200]),
                header_present: Some(vec!["x-frame-options".into()]),
                header_absent: None,
                body_regex: None,
                body_contains: Some(vec!["admin".into()]),
                title_contains: None,
            },
        };
        // Status is 200, body contains "admin", but header "x-frame-options" is missing
        let p = probe(200, make_headers(vec![("server", "nginx")]), "admin panel", None);
        assert!(!matches(&c, &p));
    }

    #[test]
    fn test_no_matchers_no_match() {
        let c = Check {
            id: "t".into(), name: "test".into(), severity: Severity::Low,
            description: "".into(),
            matchers: Matchers { status: None, header_present: None, header_absent: None, body_regex: None, body_contains: None, title_contains: None },
        };
        let p = probe(200, HashMap::new(), "", None);
        assert!(!matches(&c, &p));
    }
}

