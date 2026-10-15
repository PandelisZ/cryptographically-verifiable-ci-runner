#!/usr/bin/env sh
# Publish a release that the release workflow built as a draft, so that its
# version tag carries the manifest of its own binaries:
#
#   1. record the draft's checksums and source fingerprint in
#      release/manifest.txt (scripts/update-release-manifest.sh) and commit it;
#   2. check that commit the way the action will: its own tree's sources must be
#      the ones the binaries were built from;
#   3. push it to main, publish the draft with the version tag created on that
#      commit (so `@vX.Y.Z` and the commit SHA on the release page both install
#      the binary instead of failing), and move the major tag (v1) there too.
#
# The version tag must not exist before this runs: a tag on the commit the
# binaries were built from would point at the previous release's manifest.
#
#   gh workflow run release.yml -f tag=v1.5.0     # builds the draft release
#   scripts/publish-release.sh v1.5.0             # after it finishes
#
# Run from an up-to-date main. Pre-release tags (v2.0.0-rc1) are published as
# pre-releases and leave the major tag alone.
set -eu
tag="${1:?usage: publish-release.sh <tag>}"
repo="${VCI_REPO_SLUG:-PandelisZ/cryptographically-verifiable-ci-runner}"
remote="${VCI_RELEASE_REMOTE:-origin}"
cd "$(dirname "$0")/.."

fail() { echo "publish-release: $*" >&2; exit 1; }

case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "$tag is not a version tag such as v1.5.0" ;;
esac
[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || fail "check out main first"
if [ -n "$(git status --porcelain -- Cargo.toml Cargo.lock crates release)" ]; then
  fail "Cargo.toml, Cargo.lock, crates/ or release/ has uncommitted changes"
fi
git fetch --quiet "$remote" main
[ "$(git rev-parse HEAD)" = "$(git rev-parse FETCH_HEAD)" ] || fail "main is not $remote/main; pull or push first"
if [ -n "$(git ls-remote --tags "$remote" "refs/tags/$tag")" ]; then
  fail "$tag already exists on $remote; a version tag is created only here, on the commit that records its manifest"
fi

scripts/update-release-manifest.sh "$tag"
sed -n 's/.*) target=\([^ ]*\).*/\1/p' scripts/action-binary.sh | while IFS= read -r target; do
  grep -q "  vci-$target.tar.gz\$" release/manifest.txt || fail "the draft of $tag has no binary for $target (did a build job fail?)"
done
git add release/manifest.txt
git commit --quiet -m "Record release $tag for the action" -- release/manifest.txt
commit=$(git rev-parse HEAD)

# The action's own check, on the committed tree rather than the working tree.
tree=$(mktemp -d)
trap 'rm -rf "$tree"' EXIT
git archive "$commit" | tar -x -C "$tree"
recorded_tag=$(sed -n 's/^tag=//p' "$tree/release/manifest.txt")
recorded_source=$(sed -n 's/^source=//p' "$tree/release/manifest.txt")
own_source=$(sh "$tree/scripts/source-fingerprint.sh")
[ "$recorded_tag" = "$tag" ] || fail "$commit records $recorded_tag, not $tag"
[ "$recorded_source" = "$own_source" ] || fail "$commit has sources $own_source, but its manifest records $recorded_source"

git push --quiet "$remote" HEAD:refs/heads/main
case "$tag" in
  *-*) gh release edit "$tag" --repo "$repo" --target "$commit" --prerelease --draft=false ;;
  *) gh release edit "$tag" --repo "$repo" --target "$commit" --draft=false ;;
esac
git fetch --quiet --force "$remote" "refs/tags/$tag:refs/tags/$tag"
[ "$(git rev-parse "$tag^{commit}")" = "$commit" ] || fail "$tag on $remote is not $commit"

case "$tag" in
  *-*) echo "published pre-release $tag at $commit" ;;
  *)
    major="${tag%%.*}"
    git tag -f "$major" "$commit" >/dev/null
    git push --quiet --force "$remote" "refs/tags/$major"
    echo "published $tag at $commit; $major moved there"
    ;;
esac
