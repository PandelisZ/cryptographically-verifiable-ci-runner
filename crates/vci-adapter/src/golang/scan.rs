//! Lexical scans of Go and Go assembly sources: identifiers and numeric
//! literals outside comments and strings, `#include` lines, and the test
//! functions a `_test.go` file declares.

use std::collections::BTreeSet;

use camino::{Utf8Path, Utf8PathBuf};

/// What the code of one Go file (comments, strings and runes excluded)
/// contains.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct GoTokens {
    pub idents: BTreeSet<String>,
    /// A floating-point or imaginary literal (`0.1`, `1e9`, `0x1p-2`, `2i`).
    pub float_literal: bool,
}

fn ident_char(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// Whether a numeric literal is a floating-point or imaginary one.
fn is_float_literal(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    if l.ends_with('i') {
        return true;
    }
    if l.starts_with("0x") {
        return l.contains('p');
    }
    if l.starts_with("0b") || l.starts_with("0o") {
        return false;
    }
    l.contains('.') || l.contains('e')
}

/// Tokenise Go source text (enough of the lexical grammar to find
/// identifiers and numbers outside comments, strings and runes).
pub(crate) fn go_tokens(text: &str) -> GoTokens {
    let mut out = GoTokens::default();
    let cs: Vec<char> = text.chars().collect();
    let mut i = 0;
    let n = cs.len();
    while i < n {
        let c = cs[i];
        let next = cs.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < n && cs[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            i += 2;
            while i < n && !(cs[i] == '*' && cs.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i += 2;
        } else if c == '"' || c == '\'' {
            i += 1;
            while i < n && cs[i] != c && cs[i] != '\n' {
                if cs[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
        } else if c == '`' {
            i += 1;
            while i < n && cs[i] != '`' {
                i += 1;
            }
            i += 1;
        } else if c.is_ascii_digit() || (c == '.' && next.is_some_and(|d| d.is_ascii_digit())) {
            let start = i;
            let hex = c == '0' && matches!(next, Some('x' | 'X'));
            while i < n {
                let d = cs[i];
                let exp = if hex {
                    matches!(d, 'p' | 'P')
                } else {
                    matches!(d, 'e' | 'E')
                };
                if exp && matches!(cs.get(i + 1), Some('+' | '-')) {
                    i += 2;
                    continue;
                }
                if d.is_ascii_alphanumeric() || d == '_' || d == '.' {
                    i += 1;
                } else {
                    break;
                }
            }
            let lit: String = cs[start..i].iter().collect();
            if is_float_literal(&lit) {
                out.float_literal = true;
            }
        } else if ident_char(c) {
            let start = i;
            while i < n && ident_char(cs[i]) {
                i += 1;
            }
            out.idents.insert(cs[start..i].iter().collect());
        } else {
            i += 1;
        }
    }
    out
}

/// Identifiers whose presence means floating-point arithmetic (whose result
/// the compiler may compute differently per architecture: arm64, ppc64le,
/// s390x and riscv64 fuse `x*y + z` into one instruction, amd64 does not).
const FLOAT_IDENTS: &[&str] = &[
    "float32",
    "float64",
    "complex64",
    "complex128",
    "complex",
    "real",
    "imag",
];

impl GoTokens {
    /// The file's code refers to `GOOS` or `GOARCH` (`runtime.GOOS`, an
    /// aliased `rt.GOARCH`, `build.Default.GOOS`) or to the page size
    /// (`os.Getpagesize`: 16 KiB on macOS arm64, 4 KiB on Linux x86_64).
    pub fn platform_dependent(&self) -> bool {
        ["GOOS", "GOARCH", "Getpagesize"]
            .iter()
            .any(|i| self.idents.contains(*i))
    }

    pub fn uses_floating_point(&self) -> bool {
        self.float_literal || FLOAT_IDENTS.iter().any(|f| self.idents.contains(*f))
    }
}

/// Top-level `Test*` and `Fuzz*` functions of a `_test.go` file, by
/// `go test`'s naming rule (the prefix alone, or followed by a character
/// that is not a lower-case letter); `TestMain` excluded.
pub(crate) fn declared_tests(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("func") else {
            continue;
        };
        if !rest.starts_with([' ', '\t']) {
            continue;
        }
        let rest = rest.trim_start();
        let name: String = rest.chars().take_while(|c| ident_char(*c)).collect();
        let after = rest[name.len()..].trim_start();
        if !after.starts_with('(') || name == "TestMain" {
            continue;
        }
        for prefix in ["Test", "Fuzz"] {
            if let Some(tail) = name.strip_prefix(prefix)
                && tail.chars().next().is_none_or(|c| !c.is_lowercase())
            {
                out.insert(name.clone());
            }
        }
    }
    out
}

/// `#include "name"` lines of an assembly file or header.
pub(crate) fn asm_includes(text: &str) -> Vec<Result<String, String>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("include") else {
            continue;
        };
        let rest = rest.trim();
        let name = rest
            .strip_prefix('"')
            .and_then(|r| r.split_once('"'))
            .map(|(n, _)| n);
        out.push(match name {
            Some(n) if !n.is_empty() && !n.contains('\\') => Ok(n.to_owned()),
            _ => Err(line.trim().to_owned()),
        });
    }
    out
}

/// What the `#include`s reachable from a package's assembly files add.
#[derive(Debug, Default)]
pub(crate) struct Includes {
    /// Headers read (repository files, or outside it: refused by the caller).
    pub files: BTreeSet<Utf8PathBuf>,
    /// Paths the assembler tried first and did not find.
    pub probes: BTreeSet<Utf8PathBuf>,
    pub taints: Vec<String>,
}

/// Follow the `#include`s of `s_files` (in `pkg_dir`) as cmd/asm resolves
/// them: `go build` runs the assembler in the package directory with
/// `-I $WORK/<pkg>/ -I $GOROOT/pkg/include`, and every include (in a header
/// too) is looked up relative to the package directory, then those
/// directories. `go_asm.h` is generated from the package's Go code; headers
/// in `$GOROOT/pkg/include` belong to the Go version.
pub(crate) fn follow_includes(
    pkg_dir: &Utf8Path,
    s_files: &[String],
    goroot: &Utf8Path,
    normalise: impl Fn(&Utf8Path) -> Utf8PathBuf,
) -> Includes {
    let mut inc = Includes::default();
    let mut queue: Vec<Utf8PathBuf> = s_files.iter().map(|f| pkg_dir.join(f)).collect();
    let mut seen: BTreeSet<Utf8PathBuf> = BTreeSet::new();
    while let Some(file) = queue.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let text = match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) => {
                inc.taints.push(format!(
                    "go:asm: cannot read {file} for #include lines: {e}"
                ));
                continue;
            }
        };
        for name in asm_includes(&text) {
            let name = match name {
                Ok(n) => n,
                Err(line) => {
                    inc.taints
                        .push(format!("go:asm: {file}: cannot parse `{line}`"));
                    continue;
                }
            };
            let cand = normalise(&pkg_dir.join(&name));
            let lexical = cand.components().any(|c| {
                matches!(
                    c,
                    camino::Utf8Component::ParentDir | camino::Utf8Component::CurDir
                )
            });
            if lexical {
                inc.taints.push(format!(
                    "go:asm: {file}: #include \"{name}\" goes through a symlinked directory"
                ));
                continue;
            }
            match std::fs::metadata(&cand) {
                Ok(m) if m.is_file() => {
                    inc.files.insert(cand.clone());
                    queue.push(cand);
                    continue;
                }
                Ok(_) => {
                    inc.taints.push(format!(
                        "go:asm: {file}: #include \"{name}\" names {cand}, which is not a file"
                    ));
                    continue;
                }
                Err(_) => {}
            }
            if Utf8Path::new(&name).is_absolute() {
                inc.taints.push(format!(
                    "go:asm: {file}: #include \"{name}\" does not exist"
                ));
                continue;
            }
            if name == "go_asm.h" || goroot.join("pkg/include").join(&name).is_file() {
                inc.probes.insert(cand);
                continue;
            }
            inc.taints.push(format!(
                "go:asm: {file}: cannot resolve #include \"{name}\" (only the package directory and $GOROOT/pkg/include are searched)"
            ));
        }
    }
    inc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_outside_comments_and_strings() {
        let t = go_tokens(
            "package p\n// runtime.GOOS in a comment\nvar s = \"GOARCH\" + `float64`\nvar r = 'x'\n/* Environ */\nvar e = os.Environ\n",
        );
        assert!(t.idents.contains("Environ"));
        assert!(!t.platform_dependent(), "{t:?}");
        assert!(!t.uses_floating_point(), "{t:?}");
        assert!(go_tokens("import rt \"runtime\"\nvar x = rt.GOOS\n").platform_dependent());
        assert!(go_tokens("var x = build.Default.GOARCH").platform_dependent());
        assert!(go_tokens("n := os.Getpagesize()").platform_dependent());
    }

    #[test]
    fn floating_point_literals_and_types() {
        for (src, want) in [
            ("x := 0.1", true),
            ("x := .5", true),
            ("x := 1e9", true),
            ("x := 1E-3", true),
            ("x := 0x1p-2", true),
            ("x := 2i", true),
            ("x := 0xFF", false),
            ("x := 0xE", false),
            ("x := 1_000", false),
            ("x := 0b101", false),
            ("x := 0o17", false),
            ("x := a[1].b", false),
            ("f(xs...)", false),
            ("var f float64", true),
            ("var c = complex(1, 2)", true),
            ("x := 1 // 0.5", false),
        ] {
            assert_eq!(go_tokens(src).uses_floating_point(), want, "{src}");
        }
    }

    #[test]
    fn test_functions_by_go_test_rules() {
        let src = "package p\n\nfunc TestMain(m *testing.M) {}\nfunc TestA(t *testing.T) {}\nfunc Test(t *testing.T) {}\nfunc Test_b(t *testing.T) {}\nfunc Testing(t *testing.T) {}\nfunc FuzzX(f *testing.F) {}\nfunc helper() {}\nfunc (s *S) TestM(t *testing.T) {}\nfunc\tTestTab (t *testing.T) {}\nfunc BenchmarkX(b *testing.B) {}\n";
        assert_eq!(
            declared_tests(src).into_iter().collect::<Vec<_>>(),
            ["FuzzX", "Test", "TestA", "TestTab", "Test_b"]
        );
    }

    #[test]
    fn include_lines() {
        let r = asm_includes(
            "#include \"textflag.h\"\n  #  include \"../shared/c.h\"\n#define X 1\n#include <x.h>\n",
        );
        assert_eq!(r[0], Ok("textflag.h".to_owned()));
        assert_eq!(r[1], Ok("../shared/c.h".to_owned()));
        assert!(r[2].is_err());
    }

    #[test]
    fn includes_resolve_like_cmd_asm() {
        let t = tempfile::tempdir().unwrap();
        let r = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let goroot = r.join("goroot");
        std::fs::create_dir_all(goroot.join("pkg/include")).unwrap();
        std::fs::write(goroot.join("pkg/include/textflag.h"), "").unwrap();
        std::fs::create_dir_all(r.join("m/p")).unwrap();
        std::fs::create_dir_all(r.join("m/shared")).unwrap();
        std::fs::write(
            r.join("m/p/x_arm64.s"),
            "#include \"textflag.h\"\n#include \"go_asm.h\"\n#include \"../shared/c.h\"\n",
        )
        .unwrap();
        // Nested includes resolve relative to the package directory too.
        std::fs::write(r.join("m/shared/c.h"), "#include \"local.h\"\n").unwrap();
        std::fs::write(r.join("m/p/local.h"), "#define A 1\n").unwrap();
        let inc = follow_includes(
            &r.join("m/p"),
            &["x_arm64.s".to_owned()],
            &goroot,
            |p: &Utf8Path| crate::golang::normalise(p),
        );
        assert!(inc.taints.is_empty(), "{:?}", inc.taints);
        assert_eq!(
            inc.files.iter().collect::<Vec<_>>(),
            [&r.join("m/p/local.h"), &r.join("m/shared/c.h")]
        );
        assert!(inc.probes.contains(&r.join("m/p/textflag.h")));
        std::fs::write(r.join("m/shared/c.h"), "#include \"missing.h\"\n").unwrap();
        let inc = follow_includes(
            &r.join("m/p"),
            &["x_arm64.s".to_owned()],
            &goroot,
            |p: &Utf8Path| crate::golang::normalise(p),
        );
        assert!(
            inc.taints[0].contains("cannot resolve #include \"missing.h\""),
            "{:?}",
            inc.taints
        );
    }
}
