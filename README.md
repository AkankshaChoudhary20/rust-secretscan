# secretscan

A pre-commit-hook-ready secret scanner: finds AWS keys, GitHub tokens,
Slack tokens, private key headers, and generic high-entropy
`*_key`/`*_token`/`*_secret` assignments before they get committed.
Zero external crates -- pure std, fast to build and run.

## The problem this solves

Secrets get committed by accident constantly -- an `.env` file that wasn't
gitignored, a hardcoded API key "just for testing." Catching it at
`git commit` time, before it ever reaches a remote, is far cheaper than
catching it after.

## How it works

- **Pattern detectors**, hand-rolled (no `regex` crate): AWS access key IDs
  (`AKIA`/`ASIA` + 16 chars), GitHub tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/
  `ghr_` + 36 chars), Slack tokens (`xoxb-`/`xoxp-`/etc.), and
  `-----BEGIN ... PRIVATE KEY-----` headers.
- **Generic detector**: for anything not matching a known vendor format,
  flags `key = "..."` / `token: "..."` style assignments where the value
  has Shannon entropy > 3.5 bits/char -- catches custom/internal secret
  formats without needing a specific rule for each one.
- **Suppression**: add `# secretscan:ignore` to a line to skip it (for
  known false positives), same idea as `# nosec` / `# noqa`.
- **Redacted output**: findings show only the first/last 4 characters --
  the tool never prints the full secret to your terminal or CI logs.

## Usage

```bash
cargo build --release

# scan a directory tree (skips .git, target, node_modules, .venv, __pycache__, dist)
./target/release/secretscan .

# scan only what's staged for commit -- checks the git INDEX content,
# not the working tree, so it catches a secret even if you've since
# edited the file to remove it
./target/release/secretscan --staged
```

Exit code is `1` if anything was found (for CI/pre-commit gating), `0` if clean.

### As a pre-commit hook

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit
exec /path/to/secretscan --staged
```

## Tests

```bash
cargo test
```

26 tests, `cargo clippy --all-targets -- -D warnings` clean:

- Entropy calibration: a repeated character is 0 bits, a human name
  (`john_doe`) scores lower than a random-looking string, verified
  empirically against the actual threshold used by the generic detector.
- Every pattern detector: positive matches built with `.repeat()` to get
  exact real-world lengths (a 20-char AWS key, a 40-char GitHub token),
  plus negative cases (wrong length, plain text, public-vs-private key
  headers).
- The generic detector specifically *not* firing on a low-entropy value
  even when the variable name says "token" (`user_token = "john_doe"`),
  and *not* firing on a high-entropy value with no secret-sounding name
  nearby -- both are the false-positive traps a naive implementation
  would fall into.
- `# secretscan:ignore` suppression.
- Directory walking: `.git` excluded, nested directories included
  (temp-directory fixtures, not mocks).
- **End-to-end**: a real temp directory with a planted fake AWS key in
  one file and a clean file next to it -- scan finds exactly the one
  file, exactly the one finding.

## Real-world verification

Ran the actual compiled binary (not just `cargo test`) against:
- A directory with a real-shaped fake AWS key, a generic high-entropy API
  key, a suppressed line, and a clean file -- correctly flagged 3 findings
  across 2 rules, correctly skipped the suppressed line and clean file,
  exited `1`.
- A real git repository: staged a file containing a fake GitHub token,
  then edited the *working tree* copy to remove it, then ran
  `secretscan --staged` from inside that repo -- it still caught the
  secret, because `--staged` reads `git show :path` (the index content),
  not the working tree.

## What's intentionally not here

No git *history* scanning (only the working tree / staged index) -- a
secret already committed to history needs a different tool
(`git filter-repo`, BFG) to actually remove, not just detect. No
custom rule config file -- rules are hardcoded; adding a
TOML/YAML rule format is a reasonable next step, deliberately left out to
keep this small.
