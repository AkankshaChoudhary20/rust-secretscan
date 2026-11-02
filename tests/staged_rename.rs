use std::{fs, process::Command};

#[test]
fn staged_renames_are_scanned_even_when_original_was_clean() {
    let dir = std::env::temp_dir().join(format!("secretscan-rename-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git").current_dir(&dir).args(args).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    };
    git(&["init"]);
    let padding = "safe configuration line\n".repeat(100);
    fs::write(dir.join("old.env"), &padding).unwrap();
    git(&["add", "."]);
    git(&["-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-m", "baseline"]);
    git(&["mv", "old.env", "new.env"]);
    fs::write(dir.join("new.env"), format!("{}AWS_ACCESS_KEY_ID=AKIA{}\n", padding, "Z".repeat(16))).unwrap();
    git(&["add", "."]);
    let output = Command::new(env!("CARGO_BIN_EXE_secretscan")).current_dir(&dir).arg("--staged").output().unwrap();
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(output.status.code(), Some(1), "renamed secret was missed");
    assert!(String::from_utf8_lossy(&output.stderr).contains("new.env"));
}
