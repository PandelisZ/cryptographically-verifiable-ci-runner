#[test]
fn greets_from_the_data_file() {
    // Relative to the package directory (cargo runs tests there).
    let json = std::fs::read_to_string("tests/data/b.json").unwrap();
    assert_eq!(b::greeting(&json), Some("hello"));
}
