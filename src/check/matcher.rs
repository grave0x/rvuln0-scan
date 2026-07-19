use crate::types::{Check, Matchers, ProbeResult};
use regex::Regex;

/// Check if a probe result matches a check's matchers.
/// Path-based matching is handled by the runner, not this function.
pub fn matches(check: &Check, probe: &ProbeResult) -> bool {
    let Matchers { status, header_present, header_absent, body_regex, body_contains, title_contains, .. } = &check.matchers;

    // If no matchers defined, don't match
    if status.is_none() && header_present.is_none() && header_absent.is_none()
        && body_regex.is_none() && body_contains.is_none() && title_contains.is_none() {
        return false;
    }

    let mut all_match = true;

    if let Some(codes) = status {
        if !codes.contains(&probe.status_code) { all_match = false; }
    }
    if let Some(present) = header_present {
        for h in present { if !probe.headers.contains_key(h.as_str()) { all_match = false; } }
    }
    if let Some(absent) = header_absent {
        for h in absent { if probe.headers.contains_key(h.as_str()) { all_match = false; } }
    }
    if let Some(patterns) = body_regex {
        for pat in patterns { if let Ok(re) = Regex::new(pat) { if !re.is_match(&probe.body_preview) { all_match = false; } } }
    }
    if let Some(needles) = body_contains {
        let body_lower = probe.body_preview.to_lowercase();
        for n in needles { if !body_lower.contains(&n.to_lowercase()) { all_match = false; } }
    }
    if let Some(titles) = title_contains {
        if let Some(ref t) = probe.title {
            let t_lower = t.to_lowercase();
            for ti in titles { if !t_lower.contains(&ti.to_lowercase()) { all_match = false; } }
        } else { all_match = false; }
    }

    all_match
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;
    use std::collections::HashMap;

    fn mk(pairs: Vec<(&str, &str)>) -> HashMap<String, String> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn p(status: u16, headers: HashMap<String, String>, body: &str, title: Option<&str>) -> ProbeResult {
        ProbeResult {
            target: "http://t".into(), url: "http://t".into(), status_code: status, headers,
            body_preview: body.to_string(), content_length: body.len(),
            response_time: std::time::Duration::from_millis(10), title: title.map(|s| s.to_string()),
            tech: vec![], tls: None, error: None,
        }
    }

    fn mc(status: Option<Vec<u16>>, hp: Option<Vec<String>>, ha: Option<Vec<String>>, bc: Option<Vec<String>>, tc: Option<Vec<String>>) -> Check {
        Check { id: "t".into(), name: "t".into(), severity: Severity::Low, description: "".into(),
            matchers: Matchers { status, header_present: hp, header_absent: ha, body_regex: None, body_contains: bc, title_contains: tc, path: None } }
    }

    #[test] fn test_status_200() { assert!(matches(&mc(Some(vec![200]), None, None, None, None), &p(200, HashMap::new(), "", None))); }
    #[test] fn test_status_404() { assert!(!matches(&mc(Some(vec![404]), None, None, None, None), &p(200, HashMap::new(), "", None))); }
    #[test] fn test_header_present() { assert!(matches(&mc(None, Some(vec!["server".into()]), None, None, None), &p(200, mk(vec![("server", "n")]), "", None))); }
    #[test] fn test_header_absent() { assert!(matches(&mc(None, None, Some(vec!["x-frame".into()]), None, None), &p(200, mk(vec![("server", "n")]), "", None))); }
    #[test] fn test_body_contains() { assert!(matches(&mc(None, None, None, Some(vec!["admin".into()]), None), &p(200, HashMap::new(), "admin panel", None))); }
    #[test] fn test_title() { assert!(matches(&mc(None, None, None, None, Some(vec!["Dashboard".into()])), &p(200, HashMap::new(), "", Some("Admin Dashboard")))); }
    #[test] fn test_and_logic() { let c = mc(Some(vec![200]), Some(vec!["server".into()]), None, Some(vec!["admin".into()]), None); assert!(matches(&c, &p(200, mk(vec![("server", "n")]), "admin", None))); }
    #[test] fn test_no_match_no_matchers() { assert!(!matches(&mc(None, None, None, None, None), &p(200, HashMap::new(), "", None))); }
}
