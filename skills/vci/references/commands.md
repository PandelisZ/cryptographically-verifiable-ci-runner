# vci command reference

The help text below is the verbatim output of `vci <command> --help` for vci 1.0.0 (generated with `cargo run -p vci-cli -- <command> --help`). Notes after each block come from docs/REFERENCE.md.

## vci --help

```text
Skip CI tests that a trusted signer already ran against identical inputs

Usage: vci <COMMAND>

Commands:
  init     Write vci.toml, .vci/allowed_signers and .git-meta, configure the git-meta remote, install @vci/vitest (Vitest), print a CI snippet
  run      Run tests, collect their inputs, sign and store attestations
  plan     Decide which test files can be skipped
  ci       Plan, run the remaining tests, and write an audit log of the skips (with --key: attest what runs)
  verify   Verify one attestation envelope (file path or `-`)
  push     Publish local attestations: git-meta push (refs/meta/main) with merge and retry
  fetch    Fetch attestations: git-meta pull (fetch refs/meta/main and materialize it locally)
  prune    Delete expired attestations from the local git-meta store (publish with `vci push`)
  env      Print the effective environment policy of each project: what vci sets, hashes, ignores and removes (docs/ENV.md)
  explain  Show each candidate attestation for a test file (Go: package directory; Cargo: `<package dir>#<target>`) and the first check it failed
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## vci init

```text
Write vci.toml, .vci/allowed_signers and .git-meta, configure the git-meta remote, install @vci/vitest (Vitest), print a CI snippet

Usage: vci init [OPTIONS]

Options:
      --key <KEY>              Add this public key (or private key with a .pub next to it) to allowed_signers
      --principal <PRINCIPAL>  Principal for the key (default: git user.email)
      --project <PROJECT>      Project directory relative to the repo root
      --adapter <ADAPTER>      Test runner adapter: vitest (default), pytest, go, cargo or rails
      --no-install             Do not run npm install
      --meta-url <META_URL>    git-meta metadata remote URL for .git-meta (default: origin's URL)
  -h, --help                   Print help
```

- Writes `vci.toml` (policy and env config; left alone if it exists), adds the key to `.vci/allowed_signers` with namespace `vci-attest`, writes `.git-meta` (`url:` origin's URL unless `--meta-url`; only when the repository has an origin remote or `--meta-url` is given) and configures a git-meta remote named `meta`.
- Vitest: runs `npm install --save-dev` of the `@vci/vitest` collector unless `--no-install` (then set `VCI_JS_PLUGIN`).
- Prints a GitHub Actions example for the adapter. Commit `vci.toml`, `.vci/allowed_signers` and `.git-meta`, then merge to the default branch: CI reads trust and policy from the base commit only.
- Defaults written: `platform = "any"`, `no_skip_refs = ["refs/heads/main", "refs/tags/**"]`, env mode `strict`.

## vci run

```text
Run tests, collect their inputs, sign and store attestations

Usage: vci run [OPTIONS] [FILES]...

Arguments:
  [FILES]...  Test files, package directories for Go, `<package dir>#<target>` units or package directories for Cargo (default: all)

Options:
      --key <KEY>  SSH key for `ssh-keygen -Y sign` (private key, or .pub with the key in ssh-agent)
      --ttl <TTL>  Attestation lifetime [default: 14d]
  -h, --help       Print help
```

- Arguments are paths **relative to the current directory**: test files (Vitest, pytest, Minitest, RSpec), package directories (Go: `./b`), cargo units `<package dir>#<target>` (`crates/b#lib`, `crates/b#test:name`, `crates/b#doc`, `#bin:<name>`) or a cargo package directory (every unit of it). No arguments: every unit of every project.
- One argument that is not a listed unit stops the whole run: `<arg> is not a test file of any project (not listed by the test runner)`.
- Signing key: `--key`, else `$VCI_SIGNING_KEY`, else `git config user.signingkey` when `gpg.format = ssh` (a GPG key is never used). A `.pub` path works when the private half is in `ssh-agent`.
- Output on stderr, one line per unit: `vci: attested <unit> (<n> inputs, root <hash>) as git-meta <target> <key>` or `vci: not attesting <unit>: <reason>`, then `vci: <a> attested, <r> not attested`. Warnings start with `vci: warning:`.
- Exit code is the test runner's: non-zero if any test process failed. A refused unit with passing tests still exits 0, so read the lines.
- Attestations go into the local git-meta store (`.git/git-meta.sqlite`); nothing is shared until `vci push`.
- `--ttl` must not exceed the policy's `max_ttl` (default `30d`), or CI rejects the attestation (vci warns).
- Parallelism: `$VCI_JOBS` (pytest, Go; default CPUs up to 8). Cargo runs one unit at a time, and so does Rails (the files of a project share the test database, as in `bin/rails test`; vci does not manage that database, and its contents are not an input).

## vci plan

```text
Decide which test files can be skipped

Usage: vci plan [OPTIONS]

Options:
      --base-ref <BASE_REF>  
      --format <FORMAT>      [default: text] [possible values: text, json, github]
      --fetch [<REMOTE>]     Fetch attestations first, as `vci fetch` does, while the projects are probed (a failure is a warning: only attestations already stored locally are used). REMOTE as in `vci fetch --remote`
      --project <NAME>       Only this `[[projects]]` entry (by name; repeatable): the other projects are not listed, probed or verified. Not for the single-project form
  -h, --help                 Print help
```

- `--base-ref`: else `$VCI_BASE_REF`, else `origin/$GITHUB_BASE_REF`, else the first of `origin/HEAD`, `origin/main`, `origin/master`, `main`, `master`. Run `git fetch origin` first so the base is current.
- Text output: `SKIP <unit>  (attested by <principal> (<fingerprint>))` or `RUN  <unit>  (<reason>)`, then a summary line. Reasons include `no attestation`, `no valid attestation (N candidates; best failed <check>: ...)`, `policy.never_skip matches "<glob>"`.
- `running everything: <reason>` means no unit can skip, e.g. `policy.no_skip_refs matches refs/heads/main` (you are on main), `vci.toml is missing at the base commit`, `.vci/allowed_signers is missing at the base commit`.
- With `policy.no_skip_refs_except` set, a `no_skip_refs` ref prints `vci: note: policy.no_skip_refs matches refs/heads/main: only attestations by github-actions (policy.no_skip_refs_except) can skip` instead, and units only other signers attested show `RUN` (`... best failed signer: policy.no_skip_refs matches refs/heads/main and signer <principal> is not in no_skip_refs_except`).
- A warning when the base commit is HEAD or contains it: trust would come from the commit under test.
- `--format json`: `{baseRef, baseCommit, runAll, warnings, projects:[{name,path,adapter,runAll}], files:[{testId,file,project,skip,reason,by}]}`. Units CI will run:
  `vci plan --base-ref origin/main --format json | python3 -c 'import json,sys; [print(f["testId"]) for f in json.load(sys.stdin)["files"] if not f["skip"]]'`
- `--format github`: `::notice`/`::warning` lines and outputs for Actions.
- Reads attestations from the local store only: run `vci fetch` first to see other people's.
- `--project NAME` (repeatable; `[[projects]]` names of the base commit's vci.toml): only those projects are listed, probed and verified; the others are not touched (their toolchains need not be installed) and are absent from the output. An unknown name is an error naming the configured projects; the single-project form has no names (`--project` is an error there).

## vci ci

```text
Plan, run the remaining tests, and write an audit log of the skips (with --key: attest what runs)

Usage: vci ci [OPTIONS]

Options:
      --base-ref <BASE_REF>    
      --audit-log <AUDIT_LOG>  
      --key <KEY>              Run the remaining tests as `vci run --key` does and attest them with this SSH key (private key, or .pub with the key in ssh-agent); with run-all (e.g. policy.no_skip_refs), every unit is attested
      --ttl <TTL>              Attestation lifetime (with --key) [default: 14d]
      --push                   Afterwards publish the attestations as `vci push` does (best effort: a failure is a warning, never the exit code)
      --remote <REMOTE>        git-meta remote, or a git remote / URL, to push to (as `vci push --remote`)
      --fetch [<REMOTE>]       Fetch attestations first, as `vci fetch` does, while the projects are probed (a failure is a warning: only attestations already stored locally are used). REMOTE as in `vci fetch --remote`
      --project <NAME>         Only this `[[projects]]` entry (by name; repeatable): the other projects are not listed, probed, verified or run. Not for the single-project form
  -h, --help                   Print help
```

- `vci plan`, then runs every unit not skipped (each in its own process, the same way `vci run` ran it; Rails: a project's remaining files in one `bin/rails test <files>` or `rspec <files>` process, the engine's own way; node-test without `--key`: one `node --test` process, the package.json script's assignments and options followed by the files, printed as `vci: node-test: <command>`, or the script itself when nothing of the project is skipped) and exits non-zero if any fails. Writes a JSON audit log of every skip (signer, unit, reason) with `--audit-log`.
- Normally only run in CI (the GitHub Action runs it). Locally it is a way to run exactly what CI would run.
- `--project NAME` (repeatable) as for `vci plan`: one job per suite in a monorepo (`vci ci --fetch origin --base-ref "$BASE" --project web`); only those projects run (and are attested with `--key`) and appear in the audit log.
- When every unit is skipped it prints `vci ci: every test file is covered by a valid attestation; nothing to run` and does not start the test runner.
- `--key PATH` (CI's own key, the action's `signing-key`): the units left run as `vci run --key` runs them and every one that passed and is attestable is attested; when the plan runs everything (`running everything: ...`), every unit is. Refused or failing units still run; only test failures make the exit code non-zero. The next commit's CI skips each attested unit whose inputs did not change. `--ttl` (default `14d`) only with `--key`.
- `--push` (only with `--key`) publishes afterwards as `vci push` does, whatever the tests did; `--remote R` (only with `--push`) as `vci push --remote`. A failed push prints `::warning title=vci::could not push attestations ...` and does not change the exit code.
- A key whose principal is in `policy.no_skip_refs_except` attests nothing on a ref outside `policy.no_skip_refs` (`::warning title=vci::not attesting: the key signs as <principal>, ...`; tests still run, nothing is pushed). If attesting cannot start (unreadable key, missing collector) everything runs without attesting, with a `::warning`.
- Audit log keys added by `--key`: `attested` (`[{testId, project}]`), `attestErrors`, `notAttested`, `pushed` (`true`/`false`/`null`).
- `vci ci --key` is for CI's own key; agents attest with `vci run`. Never `--push` from a scratch clone (its git-meta remote is the upstream repository).

## vci env

```text
Print the effective environment policy of each project: what vci sets, hashes, ignores and removes (docs/ENV.md)

Usage: vci env [OPTIONS]

Options:
      --base-ref <BASE_REF>  Also compare with the policy in vci.toml at this ref
      --project <PROJECT>    Only this project (`[[projects]]` name)
      --format <FORMAT>      [default: text] [possible values: text, json]
  -h, --help                 Print help
```

- One table per project: each variable vci.toml or the runner's built-in lists name, its class (`set`, `hash`, `ignore`, `built-in hash`, `built-in ignore`, `stripped`), where the rule comes from (`vci.toml hash`, `vci.toml global (old name of hash)`, `built-in go`, `test script`, ...) and what it is here (the value vci sets; `present (<hash prefix>)` or `absent` for hashed ones). Built-in variables not set here and variables present here but removed from the tests are listed in one line each.
- `--base-ref REF`: a `BASE` column says where the policy in vci.toml at REF classifies a variable differently (CI verifies with the base policy).
- Reads vci.toml from the working tree; prints the deprecation warning for old key names (`global`, `pass_through`).

## vci explain

```text
Show each candidate attestation for a test file (Go: package directory; Cargo: `<package dir>#<target>`) and the first check it failed

Usage: vci explain [OPTIONS] <TEST_FILE>

Arguments:
  <TEST_FILE>  

Options:
      --base-ref <BASE_REF>  
  -h, --help                 Print help
```

- The argument is a unit id as `vci run` takes it (file, Go package directory, cargo `<package dir>#<target>`).
- Prints each candidate attestation (git-meta key, signer, issue and expiry times) and the first check it failed, with `expected` (what the attestation recorded) and `actual` (what this checkout computes). See `refusals.md` for every check name.
- An env failure names the variable and its class under the base policy, never its value: `env:DATABASE_URL (hash)` with `expected: blake3=...` / `actual: unset`, or `expected: not hashed` / `actual: must be hashed (env config)` when the base policy requires a variable the attestation lacks. Run `vci env --base-ref <ref>` to see the lists.
- `<unit>: not a listed test file` means the runner does not list it (wrong path, not a unit of any project).

## vci push

```text
Publish local attestations: git-meta push (refs/meta/main) with merge and retry

Usage: vci push [OPTIONS]

Options:
      --remote <REMOTE>  git-meta remote, or a git remote / URL to exchange metadata with (default: the configured git-meta remote, else .git-meta's url, else origin)
  -h, --help             Print help
```

- git-meta push of `refs/meta/main` (merge, then one fast-forward commit, retried when the remote moved). Says `nothing to push` when nothing was sent.
- Needs push access to `refs/meta/main` on the metadata remote (usually the repository itself). Push the branch separately (`git push`).
- Without a configured git-meta remote it takes the URL from `.git-meta` in the checked-out commit and prints it.

## vci fetch

```text
Fetch attestations: git-meta pull (fetch refs/meta/main and materialize it locally)

Usage: vci fetch [OPTIONS]

Options:
      --remote <REMOTE>  git-meta remote, or a git remote / URL to exchange metadata with (default: the configured git-meta remote, else .git-meta's url, else origin)
  -h, --help             Print help
```

- git-meta pull: fetches `refs/meta/main` and materializes it into `.git/git-meta.sqlite` so `vci plan`/`explain` see other signers' attestations.
- In CI always pass `--remote origin` (the action does): the checkout must not choose where attestations come from.

## vci prune

```text
Delete expired attestations from the local git-meta store (publish with `vci push`)

Usage: vci prune [OPTIONS]

Options:
      --dry-run  Only list what would be deleted
  -h, --help     Print help
```

- Deletes expired attestations from the local store as deletion records; publish them with `vci push`. Never needed for correctness: expired attestations are simply not accepted.

## vci verify

```text
Verify one attestation envelope (file path or `-`)

Usage: vci verify [OPTIONS] <ENVELOPE>

Arguments:
  <ENVELOPE>  

Options:
      --allowed-signers <ALLOWED_SIGNERS>
          Trust root (default: .vci/allowed_signers at --base-ref, or HEAD)
      --base-ref <BASE_REF>
          
  -h, --help
          Print help
```

- Verifies one DSSE envelope (a file, or `-` for stdin) and prints signer, test id, repo id, commit, input root. Mostly for debugging; `vci explain` is the usual tool.

## Environment variables

| Variable | Meaning |
|---|---|
| `VCI_SIGNING_KEY` | Default signing key for `vci run` |
| `VCI_BASE_REF` | Default base ref for `plan`, `ci`, `explain` |
| `VCI_JOBS` | Parallel test processes in `vci run` (pytest, Go; Rails files run one at a time) |
| `VCI_PY_PLUGIN`, `VCI_JS_PLUGIN`, `VCI_RUBY_COLLECTOR` | Collector locations (not needed with Homebrew) |
| `VCI_UV`, `VCI_NODE`, `VCI_GO`, `VCI_CARGO`, `VCI_RUBY` | Toolchain binaries to use |

The `[env]` policy (docs/ENV.md) is three lists: `set` (vci sets the variable in every test process, on every machine), `hash` (taken from the machine and hashed: another value re-runs) and `ignore` (taken from the machine, never hashed: put secrets there). Each runner adds a short built-in list: built-in hash (`TZ`, and per runner what the runtime reads natively, e.g. `RUSTFLAGS`, `GOFLAGS`, `PYTHONHASHSEED`, Node's `LANG`) and built-in ignore (`PATH`, `HOME`, `TMPDIR`, caches; hashed only when a test reads one). Every other variable, `CI` included, is removed from the test process in `vci run`, `vci ci` and the plan's probes. `vci env` prints the effective lists. The old names `global` and `pass_through` still work, with a warning.

