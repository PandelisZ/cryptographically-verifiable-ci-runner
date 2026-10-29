# vci command reference

The help text below is the verbatim output of `vci <command> --help` for vci 2.0.0 (generated with `cargo run -p vci-cli -- <command> --help`), except `vci store`, which is vci 2.8.0's. Notes after each block come from docs/REFERENCE.md. vci 2.8.0 also has `vci metrics` and `vci update`, and its `push`, `fetch`, `prune` and `ci --push` help mentions the stores (see "vci store info" below).

## vci --help

```text
Skip CI tests that a trusted signer already ran against identical inputs

Usage: vci <COMMAND>

Commands:
  init     Write vci.toml, .vci/allowed_signers and .git-meta, configure the git-meta remote, install @vci/vitest (Vitest), print a CI snippet (node-test: no install)
  run      Run tests, collect their inputs, sign and store attestations
  plan     Decide which test files can be skipped
  ci       Plan, run the remaining tests, and write an audit log of the skips (with --key or --oidc: attest what runs)
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
Write vci.toml, .vci/allowed_signers and .git-meta, configure the git-meta remote, install @vci/vitest (Vitest), print a CI snippet (node-test: no install)

Usage: vci init [OPTIONS]

Options:
      --key <KEY>              Add this public key (or private key with a .pub next to it) to allowed_signers
      --principal <PRINCIPAL>  Principal for the key (default: git user.email)
      --project <PROJECT>      Project directory relative to the repo root
      --adapter <ADAPTER>      Test runner adapter: vitest (default), pytest, go, cargo, rails or node-test
      --no-install             Do not run npm install
      --meta-url <META_URL>    git-meta metadata remote URL for .git-meta (default: origin's URL)
      --oidc                   Also trust this repository's GitHub Actions workflows signing keylessly (`vci ci --oidc`): write .vci/identities.toml for origin's repository and the Sigstore trust root (.vci/sigstore-trusted-root.json, from `gh attestation trusted-root`)
  -h, --help                   Print help
```

- Writes `vci.toml` (policy and env config; left alone if it exists), adds the key to `.vci/allowed_signers` with namespace `vci-attest`, writes `.git-meta` (`url:` origin's URL unless `--meta-url`; only when the repository has an origin remote or `--meta-url` is given) and configures a git-meta remote named `meta`.
- Vitest: runs `npm install --save-dev` of the `@vci/vitest` collector unless `--no-install` (then set `VCI_JS_PLUGIN`).
- Prints a GitHub Actions example for the adapter. Commit `vci.toml`, `.vci/allowed_signers` and `.git-meta`, then merge to the default branch: CI reads trust and policy from the base commit only.
- Defaults written: `platform = "any"`, `no_skip_refs = ["refs/heads/main", "refs/tags/**"]`, env mode `strict`.
- `--oidc` (since 2.0): also writes `.vci/identities.toml`, trusting pushes to origin's default branch by the repository's GitHub Actions workflow (its only file under `.github/workflows`, else `*` with a comment to narrow it) as principal `github-actions` (an existing file is left alone), and `.vci/sigstore-trusted-root.json` from `gh attestation trusted-root` (needs `gh`; otherwise a note says to write it). CI then attests keylessly with `vci ci --oidc` (the action's `oidc: true`). Review both files with the user; merge them to the default branch.

## vci run

```text
Run tests, collect their inputs, sign and store attestations

Usage: vci run [OPTIONS] [FILES]...

Arguments:
  [FILES]...  Test files, package directories for Go, `<package dir>#<target>` units or package directories for Cargo (default: all)

Options:
      --key <KEY>          SSH key for `ssh-keygen -Y sign` (private key, or .pub with the key in ssh-agent)
      --oidc[=<INSTANCE>]  Sign keylessly with the CI job's OIDC token (GitHub Actions with `permissions: id-token: write`) through Sigstore: `--oidc` or `--oidc=github` (fulcio.githubapp.com, timestamp.githubapp.com), `--oidc=public-good` (fulcio.sigstore.dev, timestamp.sigstore.dev). The instance needs the `=`, so `vci run --oidc a_test.go` runs a_test.go
      --ttl <TTL>          Attestation lifetime [default: 14d]
      --summary <SUMMARY>  Write a JSON summary of every unit (attested or not, with its reason keys) to this file
  -h, --help               Print help
```

- Arguments are paths **relative to the current directory**: test files (Vitest, pytest, Minitest, RSpec), package directories (Go: `./b`), cargo units `<package dir>#<target>` (`crates/b#lib`, `crates/b#test:name`, `crates/b#doc`, `#bin:<name>`) or a cargo package directory (every unit of it). No arguments: every unit of every project.
- One argument that is not a listed unit stops the whole run: `<arg> is not a test file of any project (not listed by the test runner)`.
- Signing key: `--key`, else `$VCI_SIGNING_KEY`, else `git config user.signingkey` when `gpg.format = ssh` (a GPG key is never used). A `.pub` path works when the private half is in `ssh-agent`.
- `--oidc` (since 2.0) signs keylessly with a GitHub Actions job's OIDC token (`permissions: id-token: write`) through Sigstore instead of a key; outside such a job it fails before running anything (`no OIDC token: ...`). It signs as the CI job's identity: agents never use it on their own (see the safety rules). `--oidc=public-good` picks sigstore.dev's instance; without `=` the next word is a file to run.
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
- Reads the attestations the local store lists: run `vci fetch` first to see other people's. Since 2.0 `vci fetch` downloads the keys only, and the plan fetches the values it reads (the candidates of the units it verifies, then their input manifests) from the metadata remote; a value that cannot be fetched (offline) makes its unit run, with a warning.
- `--project NAME` (repeatable; `[[projects]]` names of the base commit's vci.toml): only those projects are listed, probed and verified; the others are not touched (their toolchains need not be installed) and are absent from the output. An unknown name is an error naming the configured projects; the single-project form has no names (`--project` is an error there).

## vci ci

```text
Plan, run the remaining tests, and write an audit log of the skips (with --key or --oidc: attest what runs)

Usage: vci ci [OPTIONS]

Options:
      --base-ref <BASE_REF>    
      --audit-log <AUDIT_LOG>  
      --key <KEY>              Run the remaining tests as `vci run --key` does and attest them with this SSH key (private key, or .pub with the key in ssh-agent); with run-all (e.g. policy.no_skip_refs), every unit is attested
      --oidc[=<INSTANCE>]      Run the remaining tests as `vci run --oidc` does and attest them keylessly with the job's OIDC token (GitHub Actions, `permissions: id-token: write`); `--oidc=INSTANCE` as in `vci run --oidc`
      --ttl <TTL>              Attestation lifetime (with --key or --oidc) [default: 14d]
      --push                   Afterwards publish the attestations as `vci push` does (best effort: a failure is a warning, never the exit code)
      --remote <REMOTE>        git-meta remote, or a git remote / URL, to push to (as `vci push --remote`)
      --fetch [<REMOTE>]       Fetch attestations first, as `vci fetch` does, while the projects are probed (a failure is a warning: only attestations already stored locally are used). REMOTE as in `vci fetch --remote`
      --project <NAME>         Only this `[[projects]]` entry (by name; repeatable): the other projects are not listed, probed, verified or run. Not for the single-project form
      --partition <I/N>        Run only partition I of N (1-based) of the units the plan runs: a unit belongs to the partition its test id hashes to, the same in every job. Skips are the same in every partition; a project that cannot be listed runs whole in every partition that cannot list it (a warning), so its units run in some job. N jobs with `--key --push` each attest their own share
  -h, --help                   Print help
```

- `vci plan`, then runs every unit not skipped (each in its own process, the same way `vci run` ran it; Rails: a project's remaining files in one `bin/rails test <files>` or `rspec <files>` process, the engine's own way; node-test without `--key`: one `node --test` process, the package.json script's assignments and options followed by the files, printed as `vci: node-test: <command>`, or the script itself when nothing of the project is skipped) and exits non-zero if any fails. Writes a JSON audit log of every skip (signer, unit, reason) with `--audit-log`.
- Normally only run in CI (the GitHub Action runs it). Locally it is a way to run exactly what CI would run.
- `--project NAME` (repeatable) as for `vci plan`: one job per suite in a monorepo (`vci ci --fetch origin --base-ref "$BASE" --project web`); only those projects run (and are attested with `--key`) and appear in the audit log.
- When every unit is skipped it prints `vci ci: every test file is covered by a valid attestation; nothing to run` and does not start the test runner.
- `--key PATH` (CI's own key, the action's `signing-key`): the units left run as `vci run --key` runs them and every one that passed and is attestable is attested; when the plan runs everything (`running everything: ...`), every unit is. Refused or failing units still run; only test failures make the exit code non-zero. The next commit's CI skips each attested unit whose inputs did not change. `--ttl` (default `14d`) only with `--key`.
- `--oidc[=INSTANCE]` (since 2.0; the action's `oidc: true`): as `--key`, keylessly with the job's OIDC token (`permissions: id-token: write`, no secret); the job's identity must match an `[[identity]]` of the base `.vci/identities.toml`, whose principal the policy lists use like an `allowed_signers` principal. `--key` and `--oidc` exclude each other; `--ttl` and `--push` need one of them.
- `--push` (only with `--key` or `--oidc`) publishes afterwards as `vci push` does, whatever the tests did; `--remote R` (only with `--push`) as `vci push --remote`. A failed push prints `::warning title=vci::could not push attestations ...` and does not change the exit code.
- A key (or, with `--oidc`, an identity) whose principal is in `policy.no_skip_refs_except` attests nothing on a ref outside `policy.no_skip_refs` (`::warning title=vci::not attesting: the key signs as <principal>, ...`; tests still run, nothing is pushed). If attesting cannot start (unreadable key, missing collector) everything runs without attesting, with a `::warning`.
- Audit log keys added by `--key` or `--oidc`: `attested` (`[{testId, project}]`), `attestErrors`, `notAttested`, `pushed` (`true`/`false`/`null`).
- `vci ci --key` and `vci ci --oidc` are for CI's own key or identity; agents attest with `vci run --key`. Never `--push` from a scratch clone (its git-meta remote is the upstream repository).

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
- Since 2.0 it fetches the values it reads, as `vci plan` does; a candidate whose value could not be fetched fails `envelope` with ``unreadable: value not fetched: run `vci fetch` online``: run it again online.
- A keyless (CI, `--oidc`) candidate that fails `signature` or `signer` names the reason: an issuer the base `.vci/sigstore-trusted-root.json` does not list (refresh it with `gh attestation trusted-root` on the default branch), or `identity repo:... workflow:... ref:... event:... matches no [[identity]] in .vci/identities.toml`.

## vci push

```text
Publish local attestations: git-meta push (refs/meta/main) with merge and retry

Usage: vci push [OPTIONS]

Options:
      --remote <REMOTE>  git-meta remote, or a git remote / URL to exchange metadata with (default: the configured git-meta remote, else .git-meta's url, else origin)
      --rewrite-history  Publish the metadata as one commit without history (after `vci prune`: what a fetch downloads is then the current attestations, not every version ever published). Other clones merge onto it at their next fetch
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

- git-meta pull: fetches `refs/meta/main` and materializes it into `.git/git-meta.sqlite` so `vci plan`/`explain` see other signers' attestations (and, since 1.9.0, the input manifests they reference). Since 1.9.0 a fetch after an earlier one applies only the entries that changed.
- Since 2.0 it is blobless: it downloads the metadata's commits and trees (the keys), not the values; `vci plan`, `explain`, `verify`, `run` and `prune` fetch the values they read. On a store of 4,500 entries it is about 2 MB instead of 40. `N attestations stored locally` counts keys. A clone fetched by 2.0 cannot be used by vci 1.x without a refetch (docs/REFERENCE.md, "Known gaps"); a `vci-no-lazy-fetch` remote without a URL appears in `git remote` (it is how git accepts the values left out).
- In CI always pass `--remote origin` (the action does): the checkout must not choose where attestations come from.

## vci prune

```text
Delete expired attestations from the local git-meta store (publish with `vci push`)

Usage: vci prune [OPTIONS]

Options:
      --dry-run     Only list what would be deleted
      --superseded  Also delete attestations superseded by a newer one of the same unit by the same signer (their inputs no longer match the current tree, or soon will not)
  -h, --help        Print help
```

- Deletes expired attestations from the local store as deletion records; publish them with `vci push`. Never needed for correctness: expired attestations are simply not accepted.
- Since 2.0 it first fetches every attestation a blobless fetch left out (one batch; on a large store most of what a fetch downloaded before 2.0).
- Since 1.9.0 it then deletes the stored input manifests (`project` key `vci:manifest:<root>`) that no remaining attestation references and prints `vci prune: N unreferenced input manifest(s) removed` (`(dry run)` with `--dry-run`); none while an attestation cannot be read.
- Since 2.2 `--keep N` (default 2) keeps only the newest N attestations of a unit by the same signer (`--superseded` is `--keep 1`), except one made on a tree some branch or tag still has at its tip.
- Since 2.9.0 it also collects store format 3's objects: `removed project object <id> (unreferenced object)` for a hdr, tables, shape or state object no attestation references (put more than an hour ago), then `vci prune: N state object(s) older than D day(s) removed` for the state objects (the attested hashes `vci explain` prints; no verdict reads them) older than `--older-than DAYS` (default `[store] explain_hashes_days`, 2), whether or not an attestation references them. `--objects` runs only these two passes and leaves every attestation and manifest alone. On SQLite, PostgreSQL and libSQL it reads only the candidates its columns and hints name and deletes one only when its signed statement confirms them (`N unconfirmed (left alone)` otherwise); on git-meta it reads every value as before. A `--dry-run` lists the orphan objects and prints `state objects older than D day(s): removed on a run without --dry-run`.

## vci verify

```text
Verify one attestation envelope (file path or `-`)

Usage: vci verify [OPTIONS] <ENVELOPE>

Arguments:
  <ENVELOPE>  

Options:
      --allowed-signers <ALLOWED_SIGNERS>
          Trust root (default: .vci/allowed_signers at --base-ref, or HEAD)
      --identities <IDENTITIES>
          For a keyless envelope: the identities (default: .vci/identities.toml at --base-ref, or HEAD)
      --trusted-root <TRUSTED_ROOT>
          For a keyless envelope: the Sigstore trust root (default: .vci/sigstore-trusted-root.json at --base-ref, or HEAD)
      --base-ref <BASE_REF>
          
      --manifest <FILE>
          The input manifest the attestation references (its compact encoding, as `git meta get project vci:manifest:<root>` prints it). Default: read from the repository's attestation store (git-meta by default) when run inside the repository
  -h, --help
          Print help
```

- Verifies one DSSE envelope (a file, or `-` for stdin) and prints signer, test id, repo id, commit, input root. Mostly for debugging; `vci explain` is the usual tool.
- An SSH-signed envelope is checked against `.vci/allowed_signers`, a keyless one (since 2.0, a `sigstore` member) against `.vci/identities.toml` and `.vci/sigstore-trusted-root.json`, at `--base-ref` or HEAD. Once any of `--allowed-signers`, `--identities`, `--trusted-root` is given, only the given files are used: an envelope whose kind needs one that was not given is INVALID.
- Since 1.9.0 an attestation references its input manifest instead of embedding it: `vci verify` reads it from `--manifest FILE` (as `git meta get project vci:manifest:<root>` prints it) or else from the repository's attestation store, whichever it is (since 2.8.0), checks that its root is the signed input root, and exits 1 when it is missing, corrupt or another manifest. Reading the store runs `[store] token_command` and sends what it prints to `[store] url`, as every command that reads the store does, so in a checkout you have not reviewed run it with `VCI_STORE=git-meta` (SKILL.md, "Before you start"). A `--manifest FILE` in the compact encoding, built on a base manifest, reads that base from the store too.

- Since 2.9.0 the file may be a store format 3 record (the `vci3` text frame a store holds, as `vci explain --json` or a store's own tools print it): it is verified as the DSSE envelope rebuilt from it, its input set is resolved from the run's objects in the repository's store, and its root is recomputed only against `--manifest FILE` (the compact JSON of the resolved manifest); without the file it prints `root not recomputed: the attested hashes are in no signed object, pass --manifest FILE` and exits 0. `--envelope` prints the record's envelope JSON and verifies nothing (exit 0; a file that is neither a frame nor an envelope exits 2), for in-toto tooling.

## vci store info

```text
Which attestation store this repository uses ($VCI_STORE, else the scheme of $VCI_STORE_URL, else `[store] backend` in the working tree's vci.toml, else the scheme of its `[store] url`, else git-meta), every setting and where it came from (secrets redacted), what the store can do, whether it exists and how many attestations it holds. Exits 0 when the store can be read (also before anything is stored), 2 otherwise

Usage: vci store info [OPTIONS]

Options:
      --format <FORMAT>  [default: text] [possible values: text, json]
  -h, --help             Print help
```

- Since 2.8.0. Prints `store:` (`git-meta`, `sqlite`, `postgres` or `libsql`), `location:`, `settings:` (each with its
  source: `($VCI_STORE_URL)`, `(vci.toml [store])`, `(the default)`), `capabilities:`, `exchange:`, `status:`
  (`ready`, `absent: nothing is stored yet (...)` or `unavailable`) and `attestations:`. On failure it prints what it
  knows, then `vci: error: <error>`, and exits 2.
- It never prints a secret: a password or user as `***`, a token as `token: (set) ($VCI_STORE_TOKEN)` or `token: (from
  token_command: <command>) (vci.toml [store])`, PostgreSQL's as `password: (...)`. Its output is safe to show.
- It reads the store (status and count), so on a store whose credential comes from `[store] token_command` it runs that
  command once and sends what it prints to the store's URL, which `[store] url` in the checkout may name: in a checkout
  the user has not reviewed, read `[store]` in `vci.toml` instead, and run vci with `VCI_STORE=git-meta`.
- Stores without an exchange (SQLite, PostgreSQL, libSQL): `vci fetch` prints `vci: the <kind> store at <location> is
  local|shared: nothing to fetch (N attestations stored)`, `vci push` prints `vci: nothing to push: the <kind> store is
  local|shared; attestations were stored when vci run made them`, both exit 0; `--remote` and `--rewrite-history` exit
  2 there. `vci ci --fetch <remote>` and `vci ci --push --remote <remote>` ignore the remote with a warning.
- On a shared store (PostgreSQL, a libSQL server or its replica) `vci ci` without `--push` signs but stores nothing:
  `vci: not storing N attestation(s): the <kind> store is shared and vci ci was not given --push`. Plain `vci run`
  always stores.

## vci store upgrade

```text
Usage: vci store upgrade (--begin | --finish)

Options:
      --begin   Add the format-3 columns and tables (idempotent)
      --finish  Drop the input manifests and set schema version 2, once no format-1 attestation remains
```

- Since 2.9.0: the store format 3 migration of a SQLite, PostgreSQL or libSQL store (git-meta has no schema: `store:
  git-meta has no schema: nothing to upgrade`). `--begin` adds the columns and tables in a request of its own ahead
  of a rollout and prints `the format-3 columns and tables are added|present`; the first `vci run` of 2.9 does the
  same on a store that lacks them. `--finish` ends the migration window: `upgraded to schema version 2: the input
  manifests are dropped, and a vci before 2.9 reads this store as too new and fails open`, or `at schema version 2
  already`, or the refusal `not finished: N attestation(s) are not format-3 records ...` (exit 1) while a format-1
  attestation remains; on libSQL it is refused at zero too in this release. Exit 2 when the store cannot be opened.
- Both are the user's to run (SKILL.md, "Store format 3"): never run `--finish` unasked, since a 2.8 vci then fails
  open on that store for good.

## Environment variables

| Variable | Meaning |
|---|---|
| `VCI_SIGNING_KEY` | Default signing key for `vci run` |
| `SIGSTORE_ID_TOKEN` | A ready OIDC token for `--oidc` (otherwise taken from the GitHub Actions job) |
| `VCI_BASE_REF` | Default base ref for `plan`, `ci`, `explain` |
| `VCI_JOBS` | Parallel test processes in `vci run` (pytest, Go; Rails files run one at a time) |
| `VCI_PY_PLUGIN`, `VCI_JS_PLUGIN`, `VCI_RUBY_COLLECTOR` | Collector locations (not needed with Homebrew) |
| `VCI_UV`, `VCI_NODE`, `VCI_GO`, `VCI_CARGO`, `VCI_RUBY` | Toolchain binaries to use |
| `VCI_STORE` | Since 2.8.0: the attestation store, `git-meta`, `sqlite`, `postgres` or `libsql` (never a URL) |
| `VCI_STORE_URL` | **Secret.** The store's server: `postgres://user:password@host/db` or `libsql://<db>.turso.io`; wins over `vci.toml`'s `[store] url`. Never print it |
| `VCI_STORE_TOKEN` | **Secret.** A libSQL server's token; sent only to a URL from `VCI_STORE_URL`, never to `[store] url`. Never print it |
| `VCI_STORE_NAMESPACE` | A shared store's namespace (default: the repository id; required in a shallow clone) |
| `VCI_STORE_SYNC` | `replica` reads a libSQL server through a local replica; `off` turns off SQLite syncing |
| `VCI_STORE_REPLICA` | The libSQL replica's file (asks for the replica mode) |
| `VCI_STORE_CONNECT_TIMEOUT_SECS`, `VCI_STORE_TIMEOUT_SECS` | A network store's connect bound (5) and request bound (30), in seconds |
| `VCI_STORE_RECORD_FORMAT` | Since 2.9.0: `3` (the default) writes store format 3 records, `1` the envelope JSON a vci 2.8 reads, for one release; wins over `[store] record_format`. The user's choice |
| `VCI_STORE_EXPLAIN_HASHES`, `VCI_STORE_EXPLAIN_HASHES_DAYS` | Since 2.9.0: whether `vci run` writes the run's state object (`true`, the default; no verdict reads it) and the days it is kept while referenced (2, at most 365); win over `[store] explain_hashes` and `explain_hashes_days` |

The `[env]` policy (docs/ENV.md) is three lists: `set` (vci sets the variable in every test process, on every machine), `hash` (taken from the machine and hashed: another value re-runs) and `ignore` (taken from the machine, never hashed: put secrets there). Each runner adds a short built-in list: built-in hash (`TZ`, and per runner what the runtime reads natively, e.g. `RUSTFLAGS`, `GOFLAGS`, `PYTHONHASHSEED`, Node's `LANG`) and built-in ignore (`PATH`, `HOME`, `TMPDIR`, caches; hashed only when a test reads one). Every other variable, `CI` included, is removed from the test process in `vci run`, `vci ci` and the plan's probes. `vci env` prints the effective lists. The old names `global` and `pass_through` still work, with a warning.

