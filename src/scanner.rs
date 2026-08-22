//! Orchestrates running the detectors over files: turning raw text into
//! line-numbered findings, and walking a directory tree while skipping the
//! usual noise (.git, build output, dependency caches).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::detectors::{self, Finding};

#[derive(Debug, Clone)]
pub struct LineFinding {
    pub line_number: usize,
    pub finding: Finding,
}

#[derive(Debug)]
pub struct FileReport {
    pub path: PathBuf,
    pub findings: Vec<LineFinding>,
}

/// Runs every detector over each line of `text`, tagging results with
/// 1-based line numbers.
pub fn scan_text(text: &str) -> Vec<LineFinding> {
    let mut results = Vec::new();
    for (i, line) in text.lines().enumerate() {
        for finding in detectors::detect_all(line) {
            results.push(LineFinding {
                line_number: i + 1,
                finding,
            });
        }
    }
    results
}

/// Cheap binary-file heuristic: a null byte in the first chunk almost
/// certainly means "not a text file", matching what git itself uses.
pub fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8000).any(|&b| b == 0)
}

const SKIP_DIRS: [&str; 7] = [
    ".git",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
];

/// Recursively lists files under `root`, skipping well-known
/// noise/dependency directories.
pub fn walk_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk_into(root, &mut out)?;
    Ok(out)
}

fn walk_into(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk_into(&path, out)?;
        } else if file_type.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Scans one file, skipping it silently if it looks binary or isn't valid UTF-8.
pub fn scan_file(path: &Path) -> io::Result<FileReport> {
    let bytes = fs::read(path)?;
    if looks_binary(&bytes) {
        return Ok(FileReport {
            path: path.to_path_buf(),
            findings: Vec::new(),
        });
    }
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => {
            return Ok(FileReport {
                path: path.to_path_buf(),
                findings: Vec::new(),
            });
        }
    };
    Ok(FileReport {
        path: path.to_path_buf(),
        findings: scan_text(&text),
    })
}

/// Walks and scans every file under `root`. Returns only files that
/// actually have findings.
pub fn scan_directory(root: &Path) -> io::Result<Vec<FileReport>> {
    let files = walk_files(root)?;
    let mut reports = Vec::new();
    for path in files {
        let report = scan_file(&path)?;
        if !report.findings.is_empty() {
            reports.push(report);
        }
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "secretscan-test-{}-{}-{}",
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn scan_text_reports_correct_line_numbers() {
        let key = format!("AKIA{}", "C".repeat(16));
        let text = format!("line one\nline two\naws_key = \"{key}\"\nline four");
        let findings = scan_text(&text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line_number, 3);
    }

    #[test]
    fn scan_text_finds_multiple_findings_across_lines() {
        let key = format!("AKIA{}", "D".repeat(16));
        let token = format!("ghp_{}", "a".repeat(36));
        let text = format!("aws = \"{key}\"\nnothing here\ngh = \"{token}\"");
        let findings = scan_text(&text);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].line_number, 1);
        assert_eq!(findings[1].line_number, 3);
    }

    #[test]
    fn looks_binary_detects_null_byte() {
        assert!(looks_binary(&[1, 2, 0, 3]));
        assert!(!looks_binary(b"just some text"));
    }

    #[test]
    fn walk_files_skips_dot_git_and_finds_regular_files() {
        let dir = temp_dir();
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join(".git/config"), "should not be scanned").unwrap();
        fs::write(dir.join("app.py"), "print('hello')").unwrap();
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/nested.py"), "x = 1").unwrap();

        let files = walk_files(&dir).unwrap();
        let names: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(&dir).unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"app.py".to_string()));
        assert!(names.contains(&"sub/nested.py".to_string()));
        assert!(!names.iter().any(|n| n.starts_with(".git")));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_directory_end_to_end_finds_planted_secrets() {
        let dir = temp_dir();
        let key = format!("AKIA{}", "E".repeat(16));

        fs::write(
            dir.join("config.env"),
            format!("AWS_ACCESS_KEY_ID={key}\nDEBUG=true\n"),
        )
        .unwrap();
        fs::write(dir.join("readme.md"), "This file has no secrets in it.").unwrap();
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(
            dir.join(".git/HEAD"),
            format!("fake key that should be ignored {key}"),
        )
        .unwrap();

        let reports = scan_directory(&dir).unwrap();

        assert_eq!(
            reports.len(),
            1,
            "expected findings in exactly one file, got {reports:?}"
        );
        assert!(reports[0].path.ends_with("config.env"));
        assert_eq!(reports[0].findings.len(), 1);
        assert_eq!(reports[0].findings[0].finding.rule, "aws-access-key-id");

        fs::remove_dir_all(&dir).ok();
    }
}
