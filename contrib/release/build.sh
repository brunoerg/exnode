#!/bin/sh
# Builds the release tarball reproducibly (contrib/release/Dockerfile) into
# dist/: the same commit gives the same bytes on any machine.
#
#   contrib/release/build.sh                     # this machine's architecture
#   PLATFORM=linux/amd64 contrib/release/build.sh
#   contrib/release/build.sh --no-cache          # extra args go to docker buildx build
#
# Compare dist/SHA256SUMS with someone else's build of the same commit.
set -eu

root=$(git rev-parse --show-toplevel)
cd "$root"

if [ -n "$(git status --porcelain -- mix.exs mix.lock Makefile native lib rel contrib/release)" ]; then
  echo "warning: uncommitted changes in the build inputs; this build is not of a commit" >&2
fi

# Time stamps in the build come from the commit, not the clock.
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
case "$(uname -m)" in
  x86_64 | amd64) native=linux/amd64 ;;
  aarch64 | arm64) native=linux/arm64 ;;
  *) native= ;;
esac
platform=${PLATFORM:-$native}
out=${OUT:-dist}

docker buildx build \
  --file contrib/release/Dockerfile \
  ${platform:+--platform "$platform"} \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  --output "type=local,dest=$out" \
  "$@" .

echo "commit $(git rev-parse HEAD) ($platform)"
cat "$out/SHA256SUMS"
