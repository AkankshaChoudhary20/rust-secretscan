use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use secretscan::scanner::{self, FileReport};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let reports = if args.iter().any(|a| a == "--staged") {
        match scan_staged() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error scanning staged files: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        let root = args
            .iter()
            .find(|a| !a.starts_with("--"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));

        match scanner::scan_directory(&root) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error scanning {}: {e}", root.display());
                return ExitCode::FAILURE;
            }
        }
    };

    if reports.is_empty() {
        println!("no secrets found");
        return ExitCode::SUCCESS;
    }

    print_reports(&reports);
    ExitCode::FAILURE
}

/// Scans the content that's actually staged for commit (via `git show
/// :path`), not the working-tree copy -- so a pre-commit hook catches a
/// secret even if the working tree has since been edited to remove it.
fn scan_staged() -> std::io::Result<Vec<FileReport>> {
    let names_output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
        .output()?;
    if !names_output.status.success() {
        return Err(std::io::Error::other(
            String::from_utf8_lossy(&names_output.stderr).to_string(),
        ));
    }
    let names = String::from_utf8_lossy(&names_output.stdout);

    let mut reports = Vec::new();
    for path in names.lines().filter(|l| !l.is_empty()) {
        let show_output = Command::new("git")
            .args(["show", &format!(":{path}")])
            .output()?;
        if !show_output.status.success() {
            continue; // e.g. a deleted file that still shows up transiently
        }
        if scanner::looks_binary(&show_output.stdout) {
            continue;
        }
        let Ok(text) = String::from_utf8(show_output.stdout) else {
            continue;
        };
        let findings = scanner::scan_text(&text);
        if !findings.is_empty() {
            reports.push(FileReport {
                path: Path::new(path).to_path_buf(),
                findings,
            });
        }
    }
    Ok(reports)
}

fn print_reports(reports: &[FileReport]) {
    let total: usize = reports.iter().map(|r| r.findings.len()).sum();
    eprintln!("found {total} potential secret(s):\n");
    for report in reports {
        for lf in &report.findings {
            let redacted = redact(&lf.finding.matched);
            eprintln!(
                "  {}:{}  [{}]  {}",
                report.path.display(),
                lf.line_number,
                lf.finding.rule,
                redacted
            );
        }
    }
    eprintln!("\nIf any of these are false positives, add `# secretscan:ignore` to the line.");
}

/// Shows just enough of a match to identify it without leaking the whole secret.
fn redact(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(chars.len() - 8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_the_middle_of_long_secrets() {
        let key = format!("AKIA{}", "A".repeat(16));
        let r = redact(&key);
        assert!(r.starts_with("AKIA"));
        assert!(r.ends_with("AAAA"));
        assert!(r.contains('*'));
        assert!(!r.contains("AKIAAAAAAAAAAAAAAAAA")); // full secret must never appear
    }

    #[test]
    fn redact_fully_masks_short_strings() {
        assert_eq!(redact("short"), "*****");
    }
}
