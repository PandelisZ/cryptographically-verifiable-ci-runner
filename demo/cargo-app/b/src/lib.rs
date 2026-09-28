//! Crate b: its integration test reads tests/data/b.json at run time.

/// The value of `"greeting"` in a tiny JSON object.
pub fn greeting(json: &str) -> Option<&str> {
    let rest = json.split("\"greeting\"").nth(1)?;
    let start = rest.find('"')? + 1;
    let end = start + rest[start..].find('"')?;
    Some(&rest[start..end])
}
