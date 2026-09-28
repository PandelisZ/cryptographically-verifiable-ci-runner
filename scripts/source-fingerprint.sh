#!/usr/bin/env sh
# Print a fingerprint of the sources the vci binary is built from. The action
# uses it to decide whether a published release binary matches its own sources.
set -eu
cd "$(dirname "$0")/.."
if command -v sha256sum >/dev/null 2>&1; then sum="sha256sum"; else sum="shasum -a 256"; fi
find Cargo.toml Cargo.lock crates -type f -not -path '*/target/*' | LC_ALL=C sort | while IFS= read -r f; do
  printf '%s  %s\n' "$($sum < "$f" | cut -d' ' -f1)" "$f"
done | $sum | cut -c1-32
