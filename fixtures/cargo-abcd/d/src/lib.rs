//! Crate d: an external crate (hex, pinned in Cargo.lock) and crate a.

pub fn sum_hex(x: i32, y: i32) -> String {
    hex::encode(a::add(x, y).to_be_bytes())
}

#[cfg(test)]
mod tests {
    #[test]
    fn sums() {
        assert_eq!(super::sum_hex(1, 2), "00000003");
    }
}
