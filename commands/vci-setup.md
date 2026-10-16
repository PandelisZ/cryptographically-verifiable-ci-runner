---
description: Set up vci for this engineer in the current repository: install the CLI, get their SSH key trusted, verify with a plan
---

Follow the `vci-setup` skill of this plugin (skills/vci-setup/SKILL.md): install or upgrade vci, get the person's GitHub SSH key trusted in `.vci/allowed_signers` (ask before opening the pull request), check the environment with `vci env` where available, verify with `vci plan --base-ref origin/<default-branch>`, and explain the per-change loop. Ask before anything that changes something outside the working tree.
