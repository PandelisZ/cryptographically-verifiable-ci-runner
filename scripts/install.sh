#!/usr/bin/env sh
# Install vci from source: clones (or updates) the repository, builds the CLI
# with cargo, and prints the environment variables the collectors need.
#
#   curl -fsSL https://raw.githubusercontent.com/PandelisZ/cryptographically-verifiable-ci-runner/main/scripts/install.sh | sh
#
# Environment:
#   VCI_HOME  where the sources are kept (default: ~/.local/share/vci)
#   VCI_REF   branch, tag or commit to install (default: main)
#   VCI_REPO  clone URL
set -eu

VCI_HOME="${VCI_HOME:-$HOME/.local/share/vci}"
VCI_REF="${VCI_REF:-main}"
VCI_REPO="${VCI_REPO:-https://github.com/PandelisZ/cryptographically-verifiable-ci-runner.git}"

for tool in git cargo ssh-keygen; do
  command -v "$tool" >/dev/null 2>&1 || { echo "vci install: '$tool' is required but was not found" >&2; exit 1; }
done

if [ -d "$VCI_HOME/.git" ]; then
  git -C "$VCI_HOME" fetch --quiet origin "$VCI_REF"
  git -C "$VCI_HOME" checkout --quiet --detach FETCH_HEAD
else
  mkdir -p "$(dirname "$VCI_HOME")"
  git clone --quiet "$VCI_REPO" "$VCI_HOME"
  git -C "$VCI_HOME" checkout --quiet "$VCI_REF"
fi

cargo install --locked --force --path "$VCI_HOME/crates/vci-cli"

cat <<MSG

vci $(git -C "$VCI_HOME" rev-parse --short HEAD) installed to $(command -v vci || echo "~/.cargo/bin/vci").

Add these to your shell profile so vci can find its collectors:

  export VCI_PY_PLUGIN="$VCI_HOME/py/pytest-plugin"
  export VCI_JS_PLUGIN="$VCI_HOME/js/vitest-plugin"
MSG
