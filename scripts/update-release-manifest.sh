#!/usr/bin/env sh
# Record a published release in dist/release.txt so the action can download
# its binaries: the tag, the source fingerprint it was built from, and the
# SHA-256 of every asset. Run after the release workflow has finished, from a
# checkout whose crates/ are identical to the tagged commit.
#
#   scripts/update-release-manifest.sh v0.1.0
set -eu
tag="${1:?usage: update-release-manifest.sh <tag>}"
repo="${VCI_REPO_SLUG:-PandelisZ/cryptographically-verifiable-ci-runner}"
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
gh release download "$tag" --repo "$repo" --pattern 'SHA256SUMS-*' --pattern 'source-fingerprint.txt' --dir "$tmp"
built_from="$(cat "$tmp/source-fingerprint.txt")"
here="$(scripts/source-fingerprint.sh)"
if [ "$built_from" != "$here" ]; then
  echo "release $tag was built from sources $built_from, this checkout is $here" >&2
  exit 1
fi
{
  echo "# Written by scripts/update-release-manifest.sh. The action trusts only these checksums."
  echo "tag=$tag"
  echo "source=$built_from"
  cat "$tmp"/SHA256SUMS-* | LC_ALL=C sort -k2
} > dist/release.txt
cat dist/release.txt
