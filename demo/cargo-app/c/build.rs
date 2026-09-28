// Turns ../shared/c-build.txt into a constant (OUT_DIR/generated.rs).
fn main() {
    println!("cargo::rerun-if-changed=../shared/c-build.txt");
    let v = std::fs::read_to_string("../shared/c-build.txt").unwrap();
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{out}/generated.rs"),
        format!("pub const MODE: &str = {:?};\n", v.trim()),
    )
    .unwrap();
}
