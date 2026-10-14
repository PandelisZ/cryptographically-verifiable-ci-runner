# The vci agent skill

`skills/vci/` is an [Agent Skills](https://agentskills.io) skill that teaches a coding agent (Claude Code, Codex,
Cursor, Gemini CLI, GitHub Copilot, OpenCode and others) to use vci: after it changes code, it finds the test units
that cover the change, runs them with `vci run`, reads what was attested or refused, checks `vci plan`, and pushes
the attestations so CI skips those tests. It also covers setting up a repository, diagnosing "not skipped" with
`vci explain`, and the rules an agent must not break (it never edits `.vci/allowed_signers`, never weakens policy,
never attests tests it did not run or that failed).

The skill does not install vci itself. Install the CLI first (`brew install pandelisz/tap/vci`, see
[INSTALL.md](INSTALL.md)) and give the agent its own signing key (`VCI_SIGNING_KEY`), listed in
`.vci/allowed_signers` on your default branch.

```
skills/vci/
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

### Codex, Cursor and other agents without the CLI

Copy or symlink `skills/vci` into the agent's skill directory. The `skills` CLI uses `.agents/skills/` (project) and
`~/.agents/skills/` (user) for Codex, Cursor, Gemini CLI, GitHub Copilot and OpenCode; other agents have their own
directories (`.windsurf/skills/`, `.roo/skills/`, `.kiro/skills/`, ...). The skill uses only the portable
`SKILL.md` fields (`name`, `description`, `license`, `compatibility`, `metadata`).

## Using it

Ask the agent to make a change "and attest the tests with vci", or ask "why didn't CI skip tests/test_orders.py?".
The agent needs, in its environment: the `vci` binary, `VCI_SIGNING_KEY` pointing at its own key, the project's test
toolchain at the same versions as CI, and push access to `refs/meta/main` if it should share attestations.

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
- Not verified: loading the skill in a live Codex, Cursor or Gemini CLI session, and the personal-skill symlink in
  a live Claude Code session.
