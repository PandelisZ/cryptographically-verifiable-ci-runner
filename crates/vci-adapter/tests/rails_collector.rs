//! Runs the Ruby collector's own tests (`ruby/vci-collector/test`) with the
//! Ruby the Rails fixture pins: `$VCI_TEST_RUBY_BIN`, else
//! `mise where ruby@<fixtures/rails-abcd/.ruby-version>`, else `ruby` on PATH
//! if it is a Ruby 3.4. Prints `SKIPPED:` and passes when none is found.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_owned()
}

fn version(ruby: &Path) -> Option<String> {
    let out = Command::new(ruby)
        .args(["-e", "print RUBY_VERSION"])
        .env_remove("RUBYOPT")
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn find_ruby() -> Option<PathBuf> {
    let want = std::fs::read_to_string(workspace_root().join("fixtures/rails-abcd/.ruby-version"))
        .unwrap()
        .trim()
        .to_owned();
    let mut candidates = Vec::new();
    if let Some(d) = std::env::var_os("VCI_TEST_RUBY_BIN").filter(|v| !v.is_empty()) {
        candidates.push(PathBuf::from(d).join("ruby"));
    }
    if let Ok(out) = Command::new("mise")
        .args(["where", &format!("ruby@{want}")])
        .output()
        && out.status.success()
    {
        candidates.push(
            Path::new(String::from_utf8_lossy(&out.stdout).trim())
                .join("bin")
                .join("ruby"),
        );
    }
    candidates.push(PathBuf::from("ruby"));
    candidates
        .into_iter()
        .find(|r| version(r).is_some_and(|v| v.starts_with("3.4.")))
}

#[test]
fn ruby_collector_tests() {
    let Some(ruby) = find_ruby() else {
        eprintln!("SKIPPED: no Ruby 3.4 found (set VCI_TEST_RUBY_BIN or install it with mise)");
        return;
    };
    let mut cmd = Command::new(&ruby);
    cmd.arg(workspace_root().join("ruby/vci-collector/test/collector_test.rb"))
        .current_dir(workspace_root());
    for k in [
        "RUBYOPT",
        "RUBYLIB",
        "BUNDLE_GEMFILE",
        "VCI_OUT",
        "VCI_RAILS_MODE",
    ] {
        cmd.env_remove(k);
    }
    let out = cmd.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("{text}");
    assert!(out.status.success(), "ruby collector tests failed:\n{text}");
    assert!(text.contains(" 0 failures, 0 errors"), "{text}");
}
