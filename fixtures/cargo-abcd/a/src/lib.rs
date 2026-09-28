//! Crate a: pure code, no inputs besides its sources.

/// Adds two numbers.
///
/// ```
/// assert_eq!(a::add(1, 2), 3);
/// ```
pub fn add(x: i32, y: i32) -> i32 {
    x + y
}

#[cfg(test)]
mod tests {
    #[test]
    fn adds() {
        assert_eq!(super::add(2, 2), 4);
    }

    /// Ignored tests do not prevent an attestation (see the README).
    #[test]
    #[ignore = "slow"]
    fn slow() {
        assert_eq!(super::add(1, 1), 2);
    }
}
