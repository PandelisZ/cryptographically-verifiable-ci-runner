---
name: vci-setup
description: "Set up vci for the current engineer in the current repository: install or upgrade the vci CLI (brew install pandelisz/tap/vci), get their GitHub SSH key trusted in .vci/allowed_signers (open the pull request if asked), check the environment, verify with vci plan, and explain the per-change loop (vci run, vci plan, vci push). Use when someone says 'set up vci', 'onboard me to vci', 'get my key trusted', 'install vci', or after installing the vci plugin."
compatibility: Needs the vci CLI (brew install pandelisz/tap/vci), git, gh and ssh-keygen.
metadata:
  homepage: https://github.com/PandelisZ/cryptographically-verifiable-ci-runner
---

# vci setup: get one engineer ready

Set up vci for the person using this session, in the repository you are in. Do each step, report what you found, and ask before anything that changes something outside the working tree (a pull request, a shell profile).

1. **CLI.** Run `vci --version`. If it is missing or older than the version this repository's docs ask for, install or upgrade it with `brew install pandelisz/tap/vci` (or `brew upgrade pandelisz/tap/vci`); on Linux without Homebrew use the install script from the vci README.
2. **Repository.** If there is no `vci.toml` at the repository root, this repository is not set up for vci yet: say so, point at `vci init`, and stop. If there is a project-specific skill or doc for vci in this repository (for example a `vci` skill under `.claude/skills` or `.agents/skills`, or `docs/vci-quickstart.md`), follow it instead of the generic steps below.
3. **Trust.** Find the SSH key the person uses for GitHub (`ssh-add -L`, `~/.ssh/*.pub`, `gh api user/keys`) and check whether its public half is in `.vci/allowed_signers` on the default branch. If not, show the line to add (`<github-login> namespaces="vci-attest" <type> <key>`) and offer to open a pull request that appends it. Attestations are refused until that line is on the default branch.
4. **Environment.** Run `vci env` if this vci has it and report anything missing; otherwise follow the repository's docs. Never edit a shell profile without asking.
5. **Verify.** Run `vci plan --base-ref origin/<default-branch>` and explain the result in one paragraph: what would be skipped, what runs, and why.
6. **Next.** Tell the person the per-change loop: `vci run <the files or packages they touched>`, `vci plan`, `vci push`, then push the branch.
