use rvuln0_scan::{Finding, ProbeResult, Severity};

fn make_probe(status: u16, headers: Vec<(&str, &str)>, body: &str, title: Option<&str>) -> ProbeResult {
    ProbeResult {
        target: "http://test.local".into(),
        url: "http://test.local".into(),
        status_code: status,
        headers: headers.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
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
fn test_check_empty_probe() {
    let p = make_probe(200, vec![("server", "nginx")], "Hello World", None);
    let findings = rvuln0_scan::run_checks_blocking(&p, None);
    assert!(!findings.is_empty(), "Expected at least one finding for missing security headers");
}

#[test]
fn test_check_with_min_severity() {
    let p = make_probe(200, vec![("server", "nginx/1.2")], "Hello World", None);
    let findings = rvuln0_scan::run_checks_blocking(&p, Some(Severity::High));
    for f in &findings {
        assert!(f.severity.rank() >= Severity::High.rank());
    }
}

#[test]
fn test_secure_site_no_findings() {
    let p = make_probe(200, vec![
        ("server", "nginx"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("strict-transport-security", "max-age=31536000"),
        ("content-security-policy", "default-src 'self'"),
        ("cache-control", "no-cache"),
    ], "<html><body>Welcome</body></html>", Some("Home"));
    let findings = rvuln0_scan::run_checks_blocking(&p, Some(Severity::Low));
    let high_sev: Vec<_> = findings.iter().filter(|f| f.severity.rank() >= Severity::Medium.rank()).collect();
    assert!(high_sev.is_empty(), "Expected no medium+ findings, got: {:?}", high_sev);
}

#[test]
fn test_directory_listing_detected() {
    let p = make_probe(200, vec![], "Index of /\nParent Directory\nsome-file.txt", None);
    let findings = rvuln0_scan::run_checks_blocking(&p, None);
    let dir_listing: Vec<_> = findings.iter().filter(|f| f.check_id == "directory-listing").collect();
    assert_eq!(dir_listing.len(), 1, "Should detect directory listing");
}

#[test]
fn test_cors_wildcard_detected() {
    let p = make_probe(200, vec![("access-control-allow-origin", "*")], "", None);
    let findings = rvuln0_scan::run_checks_blocking(&p, None);
    let cors: Vec<_> = findings.iter().filter(|f| f.check_id == "cors-wildcard").collect();
    assert_eq!(cors.len(), 1, "Should detect CORS wildcard");
}

#[test]
fn test_tech_detection() {
    let p = ProbeResult {
        target: "http://test.local".into(),
        url: "http://test.local".into(),
        status_code: 200,
        headers: vec![("server".into(), "cloudflare".into())].into_iter().collect(),
        body_preview: String::new(),
        content_length: 0,
        response_time: std::time::Duration::from_millis(10),
        title: None,
        tech: vec![],
        tls: None,
        error: None,
    };
    let tech = rvuln0_scan::detect_tech_blocking(&p);
    assert!(tech.contains(&"Cloudflare".to_string()));
}

#[test]
fn test_report_table_format() {
    let findings = vec![Finding {
        target: "http://test.local".into(),
        check_id: "test".into(),
        check_name: "Test".into(),
        severity: Severity::High,
        description: "desc".into(),
        detail: "detail".into(),
        timestamp: "now".into(),
            risk_score: 0.0,
    }];
    let out = rvuln0_scan::format_findings_blocking(&findings, "table");
    assert!(out.contains("test"));
    assert!(out.contains("High"));
}

#[test]
fn test_report_json_format() {
    let findings = vec![Finding {
        target: "http://test.local".into(),
        check_id: "json-test".into(),
        check_name: "JSON Test".into(),
        severity: Severity::Critical,
        description: "critical issue".into(),
        detail: "detail".into(),
        timestamp: "now".into(),
            risk_score: 0.0,
    }];
    let out = rvuln0_scan::format_findings_blocking(&findings, "json");
    assert!(out.contains("json-test"));
    assert!(out.contains("Critical"));
}
