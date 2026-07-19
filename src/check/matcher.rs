use crate::types::{Check, Matchers, ProbeResult};
use regex::Regex;

/// Check if a probe result matches a check's matchers.
pub fn matches(check: &Check, probe: &ProbeResult) -> bool {
    match &check.matchers {
        Matchers {
            status,
            header_present,
            header_absent,
            body_regex,
            body_contains,
            title_contains,
        } => {
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
    }
}
