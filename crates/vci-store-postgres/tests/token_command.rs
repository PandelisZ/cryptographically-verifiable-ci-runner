//! `[store] token_command` supplies PostgreSQL's password when the URL has
//! none. The server is a stand-in that speaks the protocol's start-up far
//! enough to ask for a password in clear text and record it, so the test
//! needs no cluster (the throwaway one trusts every connection).

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use vci_store::select::{Secret, Selection, Source, Sourced, TokenCommand};
use vci_store::{AttestationStore, OpenContext, StoreError};
use vci_store_postgres::PgStore;

/// A made-up password.
const PASSWORD: &str = "pgT0kenS3cretQ7";

/// A server on 127.0.0.1 that asks every client for a clear-text password,
/// records it, and refuses it with a message that echoes it (as a careless
/// proxy might). Returns its port and what it recorded.
fn password_server() -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let got = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&got);
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                let mut len = [0u8; 4];
                if s.read_exact(&mut len).is_err() {
                    return;
                }
                let mut startup = vec![0u8; u32::from_be_bytes(len) as usize - 4];
                if s.read_exact(&mut startup).is_err() {
                    return;
                }
                // AuthenticationCleartextPassword.
                let _ = s.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3]);
                let mut head = [0u8; 5];
                if s.read_exact(&mut head).is_err() || head[0] != b'p' {
                    return;
                }
                let n = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize - 4;
                let mut body = vec![0u8; n];
                if s.read_exact(&mut body).is_err() {
                    return;
                }
                let pw =
                    String::from_utf8_lossy(body.strip_suffix(&[0]).unwrap_or(&body)).into_owned();
                let msg = format!("password authentication failed: got {pw}");
                seen.lock().unwrap().push(pw);
                let mut fields = Vec::new();
                for (k, v) in [(b'S', "FATAL"), (b'C', "28P01"), (b'M', msg.as_str())] {
                    fields.push(k);
                    fields.extend_from_slice(v.as_bytes());
                    fields.push(0);
                }
                fields.push(0);
                let mut e = vec![b'E'];
                e.extend_from_slice(&(fields.len() as u32 + 4).to_be_bytes());
                e.extend_from_slice(&fields);
                let _ = s.write_all(&e);
            });
        }
    });
    (port, got)
}

fn cx(root: &Path) -> OpenContext {
    OpenContext {
        repo_root: root.to_owned(),
        git_dir: root.join(".git"),
        git_common_dir: root.join(".git"),
        repo_id: Arc::new(|| Ok("0123456789abcdef0123456789abcdef01234567".to_owned())),
        jobs: 1,
        command: "test".to_owned(),
        long_running: false,
    }
}

/// The store at `url` (from `source`) whose password `[store] token_command`
/// prints, counting its runs in `counter`.
fn store(dir: &Path, url: &str, source: Source, counter: &Path) -> PgStore {
    let helper = dir.join("pw");
    std::fs::write(
        &helper,
        format!(
            "#!/bin/sh\necho run >> {:?}\necho {PASSWORD}\n",
            counter.to_str().unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut s = Selection::for_backend("postgres");
    s.url = Some(Sourced {
        value: Secret::new(url),
        source,
    });
    s.token_command = Some(TokenCommand::Argv(vec![
        helper.to_str().unwrap().to_owned(),
    ]));
    PgStore::open(&s, &cx(dir)).expect("open")
}

fn runs(counter: &Path) -> usize {
    std::fs::read_to_string(counter)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

#[test]
fn the_token_command_is_the_password_when_the_url_has_none() {
    let dir = std::env::temp_dir().join(format!("vci-pg-token-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let counter = dir.join("runs");
    let (port, got) = password_server();
    let url = format!("postgres://vci@127.0.0.1:{port}/ci?sslmode=disable");
    let s = store(&dir, &url, Source::File, &counter);
    assert_eq!(runs(&counter), 0, "opening runs nothing");
    // Nor does warming up (its thread is never joined, and the plan may
    // never read the store): the first read runs it.
    s.warm();
    std::thread::sleep(std::time::Duration::from_millis(800));
    assert_eq!(runs(&counter), 0, "warm() ran the token command");
    assert!(got.lock().unwrap().is_empty(), "warm() connected");
    let e = s.status().unwrap_err();
    let all = format!("{e} {e:?} {s:?} {}", s.location());
    assert!(matches!(e, StoreError::Unavailable { .. }), "{all}");
    assert_eq!(*got.lock().unwrap(), [PASSWORD], "the server got it");
    assert_eq!(runs(&counter), 1);
    assert!(
        all.contains("password authentication failed: got ***"),
        "{all}"
    );
    assert!(!all.contains(PASSWORD), "{all}");

    // A password in the URL wins: the command is never run.
    let (port, got) = password_server();
    let url = format!("postgres://vci:urlS3cretPw@127.0.0.1:{port}/ci?sslmode=disable");
    let s = store(&dir, &url, Source::Env("VCI_STORE_URL"), &counter);
    let e = s.status().unwrap_err();
    assert_eq!(*got.lock().unwrap(), ["urlS3cretPw"]);
    assert_eq!(runs(&counter), 1);
    assert!(!format!("{e} {e:?}").contains("urlS3cretPw"), "{e}");

    // A URL from vci.toml is named so in the messages about it.
    let mut s = Selection::for_backend("postgres");
    s.url = Some(Sourced {
        value: Secret::new("postgres://vci@/ci?sslmode=disable"),
        source: Source::File,
    });
    let e = PgStore::open(&s, &cx(&dir)).unwrap_err().to_string();
    assert!(
        e.contains("vci.toml [store] url") && !e.contains("$VCI_STORE_URL"),
        "{e}"
    );
    // So is it in a failure found only when connecting (a missing root
    // certificate), which the URL's parse did not see.
    let (port, _) = password_server();
    let url = format!(
        "postgres://vci@127.0.0.1:{port}/ci?sslmode=require&sslrootcert=/nonexistent/vci-ca.pem"
    );
    let s = store(&dir, &url, Source::File, &counter);
    let e = s.status().unwrap_err().to_string();
    assert!(
        e.contains("vci.toml [store] url: ") && !e.contains("$VCI_STORE_URL"),
        "{e}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
