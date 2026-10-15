#!/usr/bin/env bash
# Install the vci binary the action runs: the published release binary that
# release/manifest.txt records for exactly these sources, its SHA-256 checked
# against the manifest (part of the pinned action, so the release cannot change
# what is trusted). Called by action.yml from the action's own directory.
#
# It never compiles vci. When no published binary fits (this commit of the
# action is not a release, the download fails, the checksum differs, or the
# platform has no binary) it fails with an ::error, unless BUILD_FROM_SOURCE is
# "true": then it writes build=true and the action's next steps compile vci.
#
# The download uses `gh release download` when gh is installed (GitHub-hosted
# runners), and otherwise, or when gh fails, the public release URL with curl or
# wget (container jobs and self-hosted runners rarely have gh). Either way the
# file must match the checksum in the manifest.
#
# Environment:
#   BUILD_FROM_SOURCE  "true" lets the action compile vci when no published binary fits
#   PREBUILT           "false" (deprecated) skips the download and compiles
#   GH_TOKEN           token `gh release download` uses
#   ACTION_REPOSITORY  owner/name of the action's repository (where the release lives)
#   ACTION_REF         the ref the action was used at, for messages
#   RUNNER_OS, RUNNER_ARCH, RUNNER_TEMP, GITHUB_OUTPUT (set by the runner)
# Writes to GITHUB_OUTPUT: source=<fingerprint of the sources>, build=true|false.
set -euo pipefail
cd "$(dirname "$0")/.."

repo="${ACTION_REPOSITORY:-PandelisZ/cryptographically-verifiable-ci-runner}"
bin="$RUNNER_TEMP/vci-bin"
mkdir -p "$bin"
source=$(scripts/source-fingerprint.sh)
echo "source=$source" >> "$GITHUB_OUTPUT"

allow_build=false
[ "${BUILD_FROM_SOURCE:-false}" = "true" ] && allow_build=true
[ "${PREBUILT:-true}" = "false" ] && allow_build=true

build() {
  echo "vci: $1; compiling vci from source (build-from-source: true)"
  echo "build=true" >> "$GITHUB_OUTPUT"
  exit 0
}
# No published binary fits: compile only when allowed, otherwise fail now,
# before any toolchain or cache work.
unavailable() {
  if [ "$allow_build" = "true" ]; then
    build "$1"
  fi
  echo "::error title=vci::$2"
  echo "build=false" >> "$GITHUB_OUTPUT"
  exit 1
}

if [ "${PREBUILT:-true}" = "false" ]; then
  build "prebuilt is false (deprecated: use build-from-source)"
fi

ref="${ACTION_REF:-}"
if [ -z "$ref" ]; then
  ref=$(git rev-parse HEAD 2>/dev/null || echo "unknown commit")
fi
manifest=release/manifest.txt
tag=""
built_from=""
if [ -f "$manifest" ]; then
  tag=$(sed -n 's/^tag=//p' "$manifest")
  built_from=$(sed -n 's/^source=//p' "$manifest")
fi
major="${tag%%.*}"
major="${major:-v1}"
# Only the major tag is named: it always points at a commit whose manifest
# records its own sources. Version tags do so only from the first release
# published with scripts/publish-release.sh on; v1.0.0 to v1.4.0 point at the
# commit before their manifest was recorded.
use_release="Use a release: uses: $repo@$major, or the full commit SHA $major points to (git ls-remote https://github.com/$repo refs/tags/$major). To compile vci in this job anyway, set build-from-source: true."

if [ -z "$tag" ] || [ -z "$built_from" ]; then
  unavailable "no release recorded in $manifest" \
    "vci: this commit of the action ($ref, sources $source) has no published binary ($manifest records no release). $use_release"
fi
if [ "$built_from" != "$source" ]; then
  unavailable "release $tag was built from sources $built_from, not $source" \
    "vci: this commit of the action ($ref, sources $source) has no published binary ($manifest records $tag built from $built_from). $use_release"
fi

case "${RUNNER_OS:-}-${RUNNER_ARCH:-}" in
  Linux-X64) target=x86_64-unknown-linux-musl ;;
  Linux-ARM64) target=aarch64-unknown-linux-musl ;;
  macOS-ARM64) target=aarch64-apple-darwin ;;
  macOS-X64) target=x86_64-apple-darwin ;;
  *)
    unavailable "no release binary for ${RUNNER_OS:-}-${RUNNER_ARCH:-}" \
      "vci: release $tag has no binary for ${RUNNER_OS:-}-${RUNNER_ARCH:-} (published: Linux and macOS, X64 and ARM64). To compile vci in this job, set build-from-source: true."
    ;;
esac
asset="vci-$target.tar.gz"
want=$(awk -v a="$asset" '$2 == a { print $1 }' "$manifest")
if [ -z "$want" ]; then
  unavailable "no checksum recorded for $asset" \
    "vci: $manifest records no checksum for $asset of release $tag, so it cannot be verified. $use_release"
fi

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
url="https://github.com/$repo/releases/download/$tag/$asset"
# Returns 2 when there is nothing to download with; on failure `tried` says
# what was attempted.
download() {
  tried=""
  if command -v gh >/dev/null 2>&1; then
    if gh release download "$tag" --repo "$repo" --pattern "$asset" --dir "$dir"; then
      return 0
    fi
    rm -f "$dir/$asset"
    tried="gh release download failed (the token input may not be able to read the releases of $repo)"
    echo "vci: gh release download failed; trying $url"
  else
    tried="gh is not installed"
  fi
  if command -v curl >/dev/null 2>&1; then
    if curl -fsSL --retry 3 -o "$dir/$asset" "$url"; then
      return 0
    fi
    tried="$tried; curl $url failed"
  elif command -v wget >/dev/null 2>&1; then
    if wget -q -O "$dir/$asset" "$url"; then
      return 0
    fi
    tried="$tried; wget $url failed"
  elif command -v gh >/dev/null 2>&1; then
    tried="$tried, and neither curl nor wget is installed to try $url"
  else
    return 2
  fi
  rm -f "$dir/$asset"
  return 1
}
status=0
download || status=$?
if [ "$status" -eq 2 ]; then
  unavailable "nothing to download $asset with (gh, curl or wget)" \
    "vci: cannot download $asset of release $tag: this job has none of gh, curl or wget on the PATH. Install curl in the job (e.g. in its container image), or set build-from-source: true to compile vci in this job instead."
elif [ "$status" -ne 0 ]; then
  [ "$allow_build" = "true" ] && echo "::warning title=vci::could not download $asset of release $tag from $repo ($tried)"
  unavailable "could not download $asset" \
    "vci: could not download $asset of release $tag from $repo ($tried; see the output above). Re-run the job if this was a network failure, or set build-from-source: true to compile vci in this job instead."
fi
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$dir/$asset" | cut -d' ' -f1)
else
  got=$(shasum -a 256 "$dir/$asset" | cut -d' ' -f1)
fi
if [ "$got" != "$want" ]; then
  [ "$allow_build" = "true" ] && echo "::warning title=vci::checksum mismatch for $asset: expected $want, got $got"
  unavailable "checksum mismatch for $asset" \
    "vci: $asset of release $tag does not match the checksum in $manifest (expected $want, got $got); it was not installed."
fi
tar -C "$bin" -xzf "$dir/$asset" vci
echo "using vci $tag ($asset, sha256 $got)"
echo "build=false" >> "$GITHUB_OUTPUT"
