//! Hand-rolled pattern matchers for common secret formats -- no regex crate,
//! since these shapes (fixed prefix + fixed-length alphanumeric suffix) are
//! simple enough to check with plain string/char operations, and it keeps
//! this a zero-dependency, fast-to-build tool.

use crate::entropy::shannon_entropy;

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub rule: &'static str,
    /// Byte offset into the line where the match starts.
    pub start: usize,
    pub matched: String,
}

fn is_alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// Finds every maximal run of alnum/`_`/`-` characters in `line` and calls
/// `check` on each candidate; candidates for which `check` returns Some(rule)
/// become findings.
fn scan_tokens(
    line: &str,
    min_len: usize,
    check: impl Fn(&str) -> Option<&'static str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if is_alnum(bytes[i] as char) || bytes[i] == b'_' || bytes[i] == b'-' {
            let start = i;
            while i < bytes.len()
                && (is_alnum(bytes[i] as char) || bytes[i] == b'_' || bytes[i] == b'-')
            {
                i += 1;
            }
            let token = &line[start..i];
            if token.len() >= min_len
                && let Some(rule) = check(token)
            {
                findings.push(Finding {
                    rule,
                    start,
                    matched: token.to_string(),
                });
            }
        } else {
            i += 1;
        }
    }
    findings
}

pub fn detect_aws_key(line: &str) -> Vec<Finding> {
    scan_tokens(line, 20, |token| {
        if token.len() != 20 {
            return None;
        }
        let prefix_ok = token.starts_with("AKIA") || token.starts_with("ASIA");
        let rest_ok = token[4..]
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
        (prefix_ok && rest_ok).then_some("aws-access-key-id")
    })
}

const GITHUB_PREFIXES: [&str; 5] = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"];

pub fn detect_github_token(line: &str) -> Vec<Finding> {
    scan_tokens(line, 40, |token| {
        GITHUB_PREFIXES
            .iter()
            .any(|p| token.starts_with(p) && token.len() >= 40 && token[4..].chars().all(is_alnum))
            .then_some("github-token")
    })
}

const SLACK_PREFIXES: [&str; 5] = ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"];

pub fn detect_slack_token(line: &str) -> Vec<Finding> {
    scan_tokens(line, 20, |token| {
        SLACK_PREFIXES
            .iter()
            .any(|p| token.starts_with(p) && token.len() >= 20)
            .then_some("slack-token")
    })
}

pub fn detect_private_key_header(line: &str) -> Vec<Finding> {
    let trimmed = line.trim();
    if trimmed.starts_with("-----BEGIN") && trimmed.ends_with("PRIVATE KEY-----") {
        vec![Finding {
            rule: "private-key-header",
            start: line.find("-----BEGIN").unwrap_or(0),
            matched: trimmed.to_string(),
        }]
    } else {
        vec![]
    }
}

const SECRET_NAME_HINTS: [&str; 8] = [
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "access_key",
    "credential",
];

/// Catches `SOME_KEY = "highEntropyValue"` / `SOME_KEY: "..."` style
/// assignments where the variable name suggests a secret and the value
/// looks randomly generated, regardless of vendor-specific format.
pub fn detect_generic_secret_assignment(line: &str) -> Vec<Finding> {
    let Some(sep_pos) = line.find(['=', ':']) else {
        return vec![];
    };
    let name = line[..sep_pos].to_lowercase();
    if !SECRET_NAME_HINTS.iter().any(|hint| name.contains(hint)) {
        return vec![];
    }
    let value_part = &line[sep_pos + 1..];

    scan_tokens(value_part, 16, |token| {
        let entropy = shannon_entropy(token);
        (entropy > 3.5).then_some("generic-high-entropy-secret")
    })
    .into_iter()
    .map(|mut f| {
        f.start += sep_pos + 1;
        f
    })
    .collect()
}

/// Runs every detector against `line`. Lines containing the suppression
/// marker are skipped entirely (a deliberate escape hatch for known false
/// positives, same idea as `# nosec` / `# noqa`).
pub fn detect_all(line: &str) -> Vec<Finding> {
    if line.contains("secretscan:ignore") {
        return vec![];
    }

    let mut findings = Vec::new();
    findings.extend(detect_aws_key(line));
    findings.extend(detect_github_token(line));
    findings.extend(detect_slack_token(line));
    findings.extend(detect_private_key_header(line));
    findings.extend(detect_generic_secret_assignment(line));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_access_key() {
        let key = format!("AKIA{}", "A".repeat(16)); // 20 chars total
        let line = format!("aws_access_key_id = \"{key}\"");
        let findings = detect_aws_key(&line);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "aws-access-key-id");
        assert_eq!(findings[0].matched, key);
    }

    #[test]
    fn does_not_flag_wrong_length_akia_prefix() {
        let line = "AKIA_TOO_SHORT";
        assert!(detect_aws_key(line).is_empty());
    }

    #[test]
    fn does_not_flag_plain_text() {
        assert!(detect_aws_key("just a normal sentence about cats").is_empty());
    }

    #[test]
    fn detects_github_token() {
        let token = format!("ghp_{}", "a".repeat(36)); // 40 chars total
        let line = format!("GITHUB_TOKEN={token}");
        let findings = detect_github_token(&line);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "github-token");
    }

    #[test]
    fn github_token_too_short_not_flagged() {
        let line = "GITHUB_TOKEN=ghp_tooshort";
        assert!(detect_github_token(line).is_empty());
    }

    #[test]
    fn detects_slack_token() {
        let token = format!("xoxb-{}", "1".repeat(20));
        let line = format!("SLACK_BOT_TOKEN=\"{token}\"");
        let findings = detect_slack_token(&line);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "slack-token");
    }

    #[test]
    fn detects_private_key_header() {
        let line = "-----BEGIN RSA PRIVATE KEY-----";
        let findings = detect_private_key_header(line);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "private-key-header");
    }

    #[test]
    fn does_not_flag_public_key_header() {
        // Public keys are not secrets; only PRIVATE KEY headers should fire.
        let line = "-----BEGIN PUBLIC KEY-----";
        assert!(detect_private_key_header(line).is_empty());
    }

    #[test]
    fn detects_generic_high_entropy_secret_assignment() {
        let line = "api_key = \"aB3xZ9pQr7mN2kLj8FhTz1Qw\"";
        let findings = detect_generic_secret_assignment(line);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one finding, got {findings:?}"
        );
        assert_eq!(findings[0].rule, "generic-high-entropy-secret");
    }

    #[test]
    fn does_not_flag_low_entropy_value_even_with_secret_name() {
        let line = "user_token = \"john_doe_the_developer\"";
        assert!(
            detect_generic_secret_assignment(line).is_empty(),
            "a human-readable value assigned to a *_token variable should not be flagged"
        );
    }

    #[test]
    fn does_not_flag_high_entropy_value_without_secret_name_hint() {
        let line = "description = \"aB3xZ9pQr7mN2kLj8FhTz1Qw\"";
        assert!(
            detect_generic_secret_assignment(line).is_empty(),
            "a high-entropy value with no key/token/secret hint in the line should not be flagged"
        );
    }

    #[test]
    fn secret_name_hint_must_be_on_the_assignment_name() {
        let value = "aB3xZ9pQr7mN2kLj8FhTz1Qw";
        let line = format!("description = \"{value}\" # token from a public example");
        assert!(detect_generic_secret_assignment(&line).is_empty());
        let line = format!("description = \"secret{value}\"");
        assert!(detect_generic_secret_assignment(&line).is_empty());
        let line = format!("API_TOKEN = \"{value}\"");
        assert_eq!(detect_generic_secret_assignment(&line).len(), 1);
    }

    #[test]
    fn suppression_marker_skips_the_whole_line() {
        let key = format!("AKIA{}", "A".repeat(16));
        let line = format!("aws_access_key_id = \"{key}\" # secretscan:ignore");
        assert!(detect_all(&line).is_empty());
    }

    #[test]
    fn detect_all_combines_every_detector() {
        let line = "hello world, nothing secret here";
        assert!(detect_all(line).is_empty());
    }

    #[test]
    fn detect_all_finds_a_real_looking_finding() {
        let key = format!("AKIA{}", "B".repeat(16));
        let line = format!("  key = \"{key}\"  ");
        let findings = detect_all(&line);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.rule == "aws-access-key-id"));
    }
}
