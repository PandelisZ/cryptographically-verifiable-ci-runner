# The vci agent skill

`skills/vci/` is an [Agent Skills](https://agentskills.io) skill that teaches a coding agent (Claude Code, Codex,
Cursor, Gemini CLI, GitHub Copilot, OpenCode and others) to use vci: after it changes code, it finds the test units
that cover the change, runs them with `vci run`, reads what was attested or refused, checks `vci plan`, and pushes
the attestations so CI skips those tests. It also covers setting up a repository, diagnosing "not skipped" with
`vci explain`, the attestation stores of vci 2.8 (below), and the rules an agent must not break (it never edits
`.vci/allowed_signers`, never weakens policy, never attests tests it did not run or that failed, never prints a
store credential).

The skill does not install vci itself. Install the CLI first (`brew install pandelisz/tap/vci`, see
[INSTALL.md](INSTALL.md)) and give the agent its own signing key (`VCI_SIGNING_KEY`), listed in
`.vci/allowed_signers` on your default branch.

```
skills/vci/                      # the skill (.agents/skills/vci is a symlink to it, for Codex)
├── SKILL.md                     # the workflow, mental model, safety rules
├── references/
│   ├── commands.md              # verbatim `vci <command> --help` plus notes
│   ├── runners.md               # unit ids, inputs, refusals and pins per runner
│   ├── refusals.md              # every "not attesting" reason and "failed check"
│   └── ci-setup.md              # vci init, allowed_signers, GitHub Actions
└── scripts/
    └── units-for-change.sh      # changed files -> candidate units (git diff based)
```

## Install

Three routes, by agent:

| Agent | Route |
|---|---|
| Claude Code | the plugin from this repository's marketplace (`/plugin install vci@pandelisz`), or a personal or project skill |
| Codex | `$skill-installer` with this repository's GitHub path, or copy `skills/vci` into `~/.agents/skills/vci` or a repository's `.agents/skills/vci` |
| Any agent (Claude Code, Codex, Cursor, ...) | `npx skills add PandelisZ/cryptographically-verifiable-ci-runner` |

To give a whole team the skill, commit it into your repository instead: see
[Distribute to your org](#distribute-to-your-org).

### Any agent: the `skills` CLI

[`skills`](https://github.com/vercel-labs/skills) (by Vercel) installs a skill from a GitHub repository into the
skill directory of each agent you use. It finds `skills/vci/SKILL.md` without any manifest.

```sh
npx skills add PandelisZ/cryptographically-verifiable-ci-runner                     # pick agents interactively
npx skills add PandelisZ/cryptographically-verifiable-ci-runner --skill vci -g -y   # every detected agent, user-wide
npx skills add PandelisZ/cryptographically-verifiable-ci-runner --list              # show the skills, install nothing
```

- Without `-g` the skill goes into the current project (`.agents/skills/vci`, plus a `.claude/skills/vci` symlink for
  Claude Code) and a `skills-lock.json` is written; commit them to share the skill with your team.
- With `-g` it goes into your home directory (`~/.agents/skills/vci`, plus `~/.claude/skills/vci` for Claude Code).
- Choose agents with `--agent`, for example `--agent claude-code codex cursor`. Agent ids include `claude-code`,
  `codex`, `cursor`, `gemini-cli`, `github-copilot`, `opencode`, `windsurf`, `roo`, `goose`, `kiro-cli`, `amp`; run
  `npx skills --help` or see the CLI's README for the full list and each agent's directory.
- `--copy` copies the files instead of symlinking them. Update later with `npx skills update`, remove with
  `npx skills remove vci`.

### Claude Code: personal skill

```sh
git clone https://github.com/PandelisZ/cryptographically-verifiable-ci-runner.git ~/.local/share/vci-skill
mkdir -p ~/.claude/skills
ln -s ~/.local/share/vci-skill/skills/vci ~/.claude/skills/vci      # or: cp -R ... to copy instead
```

If you used the install script, the vci checkout already exists:
`ln -s ~/.local/share/vci/skills/vci ~/.claude/skills/vci`. Update with `git pull` in the checkout.

For one repository only, put it in the project instead: `.claude/skills/vci/` (copy `skills/vci` there and commit
it). Claude Code uses the skill automatically when a task matches, or run it as `/vci`.

### Claude Code: plugin

This repository is also a Claude Code plugin marketplace (`.claude-plugin/marketplace.json`, marketplace name
`pandelisz`) with one plugin, `vci`, that bundles the skill. In a Claude Code session:

```text
/plugin marketplace add PandelisZ/cryptographically-verifiable-ci-runner
/plugin install vci@pandelisz
```

Or from your shell:

```sh
claude plugin marketplace add PandelisZ/cryptographically-verifiable-ci-runner
claude plugin install vci@pandelisz
```

As a plugin the skill is namespaced: `/vci:vci`. The plugin has no `version`, so its version is the commit it was
installed from; get newer commits with `claude plugin marketplace update pandelisz` then
`claude plugin update vci@pandelisz` (third-party marketplaces do not auto-update unless you turn it on in
`/plugin`).

### Codex

Codex reads skills from `.agents/skills/<name>/SKILL.md` in every directory from the current one up to the repository
root, and from `~/.agents/skills/` for the user; it follows symlinked skill folders. This repository has
`.agents/skills/vci` (a symlink to `skills/vci`), so Codex offers the skill in a clone of it without any install.
Elsewhere, pick one:

- Ask the built-in installer for it by GitHub path, in a Codex session:

  ```text
  $skill-installer install https://github.com/PandelisZ/cryptographically-verifiable-ci-runner/tree/main/skills/vci
  ```

- Copy it for yourself (every repository):

  ```sh
  git clone https://github.com/PandelisZ/cryptographically-verifiable-ci-runner.git ~/.local/share/vci-skill
  mkdir -p ~/.agents/skills
  cp -R ~/.local/share/vci-skill/skills/vci ~/.agents/skills/vci     # or ln -s to follow `git pull`
  ```

- Copy it into one repository: `cp -R skills/vci <repo>/.agents/skills/vci` and commit it.

Codex picks up a new skill on its own; restart it if the skill does not appear. Codex requires only `name` and
`description` in the frontmatter, which the skill has. Codex's optional `agents/openai.yaml` (display name, default
prompt, invocation policy) is not needed.

### Cursor and other agents

Copy or symlink `skills/vci` into the agent's skill directory. The `skills` CLI uses `.agents/skills/` (project) and
`~/.agents/skills/` (user) for Codex, Cursor, Gemini CLI, GitHub Copilot and OpenCode; other agents have their own
directories (`.windsurf/skills/`, `.roo/skills/`, `.kiro/skills/`, ...). The skill uses only the portable
`SKILL.md` fields (`name`, `description`, `license`, `compatibility`, `metadata`).

## Distribute to your org

Engineers should not each have to find and install the skill. Commit it into the repository where vci runs, once,
at the paths both agents read, with one real copy:

```sh
mkdir -p .agents/skills .claude/skills
cp -R <vci checkout>/skills/vci .agents/skills/vci     # the copy Codex reads
ln -s ../../.agents/skills/vci .claude/skills/vci      # Claude Code follows the symlink
git add .agents/skills/vci .claude/skills/vci
```

(`npx skills add PandelisZ/cryptographically-verifiable-ci-runner --skill vci --agent claude-code codex -y` produces
the same layout and records the source in `skills-lock.json`.) Every engineer who opens the repository in Codex or
Claude Code then has the skill, and updates arrive with `git pull`.

Then make it yours. The generic skill knows vci; it does not know your repository. Teams get the most from a skill
that also states, in its body:

- the default branch (`origin/master` or `origin/main`) and that it never skips;
- each project in `vci.toml`, its unit ids and how slow its units are;
- the environment values to export (or `vci env`, when vci has it), and services such as a test database;
- how an engineer gets their key into `.vci/allowed_signers`: who reviews it, and the principal to use.

The vex monorepo does this: its `vci` skill sits at `.agents/skills/vci` with `.claude/skills/vci` linking to it,
adds its own projects and gotchas, and ships `scripts/setup.sh`, which sets up each engineer: it installs or upgrades
vci, finds the SSH key GitHub knows for them, opens the pull request that adds it to `.vci/allowed_signers`, checks
the environment and runs `vci plan` (`--check` reports only, `--dry-run` prints every action, `--no-pr` skips the
pull request, and the shell profile is written only by a separate, profile-only `--write-profile` run). An engineer
says "set up vci" to their agent and is done after one review. Keep a repository skill's name `vci` only if engineers
do not also install the generic one, or rename it (`<repo>-vci`) so the two are not confused.

## Using it

Ask the agent to make a change "and attest the tests with vci", or ask "why didn't CI skip tests/test_orders.py?".
The agent needs, in its environment: the `vci` binary, `VCI_SIGNING_KEY` pointing at its own key, the project's test
toolchain at the same versions as CI, and push access to `refs/meta/main` if it should share attestations.

### Attestation stores

Since vci 2.8.0 a repository can keep its attestations in a SQLite file, on PostgreSQL or in a libSQL database (Turso)
instead of git-meta ([REFERENCE.md, "Where attestations live"](REFERENCE.md#where-attestations-live); the setup guide is
the site's `stores.html`). `SKILL.md` has a section, "Attestation stores", that tells the agent:

- to find out which store a repository uses with `vci store info`, whose output never holds a secret and is safe to
  show;
- never to print, paste or commit `VCI_STORE_URL`, `VCI_STORE_TOKEN` or what a `[store] token_command` prints, and
  never to put a credential in `vci.toml`;
- to see why a token command failed by running it with its standard output discarded
  (`com secrets get vci-store-token --org vex > /dev/null`), which is what vci's message says since 2.8.1;
- that `vci push` publishes on git-meta only, that `vci run` stores at once on the other stores, and that `vci ci
  --push` is for trusted CI jobs;
- that a plan which says `running everything: reading attestations from <kind>: …` failed open, which is safe;
- and, when asked to set up Turso, to pipe tokens from `turso db tokens create` into `gh secret set` on standard input,
  never as an argument, asking before each command that creates a database, token, environment or secret.

On a repository whose `vci.toml` has `[store] url` and `token_command`, the agent needs no store variable in its
environment: sign its machine in to the tool the command uses (`com login`, `op signin`). Give it a read-only token
if it should plan but not store; its `vci run` then runs the tests and stores nothing.

The helper script can be run by hand too:

```sh
skills/vci/scripts/units-for-change.sh            # units covering the changes since the merge base with origin/main
vci run $(skills/vci/scripts/units-for-change.sh) --key ~/.ssh/id_ed25519   # from the repository root
```

## What was verified

Checked on macOS arm64 on 2026-10-13, before the skill was pushed:

- `SKILL.md` passes the Agent Skills reference validator (`uvx --from skills-ref agentskills validate skills/vci`,
  skills-ref 0.1.1): `name` matches the directory, description 703 characters (limit 1024).
- `skills` CLI 1.7.2: `npx skills add <this checkout> --list` and `npx skills add file://<a clone with the skill
  committed> --list` both find exactly one skill, `vci`; a project install (`--skill vci --agent claude-code codex
  cursor -y`) wrote `.agents/skills/vci` with the script still executable and a `.claude/skills/vci` symlink; a global
  install with a temporary `HOME` wrote `~/.agents/skills/vci` and `~/.claude/skills/vci`. `npx skills add
  PandelisZ/cryptographically-verifiable-ci-runner --list` found no skill at that time because the files were not yet
  on GitHub; after they are pushed it should behave like the clone test.
- Claude Code 2.1.282: `claude plugin validate .` passes (one warning: no `version`, which is intentional so installs
  follow commits); `claude plugin marketplace add <this checkout>` then `claude plugin install vci@pandelisz`, in an
  isolated `CLAUDE_CONFIG_DIR`, installed the plugin, and `claude plugin details vci` lists one skill, `vci`. The
  GitHub form (`/plugin marketplace add PandelisZ/...`) was not tried before the push.
- `scripts/units-for-change.sh` was run against every demo project in `demo/` (pytest, Go, Cargo, Rails Minitest,
  RSpec) and a scratch Vitest-shaped repository, in both git-diff and explicit-path modes, under macOS's bash 3.2.
- The skill's workflow was run end to end in a scratch clone with a throwaway key: `units-for-change.sh` →
  `vci run demo/go-app/b` (attested) → `vci plan` → `vci explain` (`failed check: signer`, as expected for a key that
  is not in the base branch's `allowed_signers`), and the `--format json` one-liner.
- Checked on 2026-10-15: with the `.agents/skills/vci` symlink added, `npx skills add <this checkout> --list`
  (skills CLI 1.7.2) still finds exactly one skill, `vci`. Codex's skills documentation says it scans `.agents/skills`
  from the working directory to the repository root and follows symlinked skill folders; Claude Code's says a
  project or personal skill entry can be a symlink to a directory.
- Not verified: loading the skill in a live Codex, Cursor or Gemini CLI session, `$skill-installer` with the GitHub
  path, and the personal-skill symlink in a live Claude Code session.
