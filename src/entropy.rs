//! Shannon entropy, used to distinguish "randomly generated secret" from
//! "a human-readable name assigned to a variable that happens to be called
//! `token`" -- e.g. `user_token = "john_doe"` shouldn't fire, but
//! `api_key = "aB3xZ9pQr7mN2kLj8FhT"` should.

use std::collections::HashMap;

/// Shannon entropy of `s` in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = s.chars().count() as f64;
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_character_has_zero_entropy() {
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
    }

    #[test]
    fn empty_string_has_zero_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn random_looking_string_has_high_entropy() {
        let e = shannon_entropy("aB3xZ9pQr7mN2kLj8FhT");
        assert!(e > 3.5, "expected high entropy, got {e}");
    }

    #[test]
    fn common_word_has_lower_entropy_than_random_string() {
        let word = shannon_entropy("password");
        let random = shannon_entropy("qX7mK2pL9vN4wJ8h");
        assert!(
            word < random,
            "word entropy {word} should be lower than random entropy {random}"
        );
    }

    #[test]
    fn human_name_has_low_entropy() {
        let e = shannon_entropy("john_doe");
        assert!(e < 3.5, "expected low entropy for a name, got {e}");
    }
}
