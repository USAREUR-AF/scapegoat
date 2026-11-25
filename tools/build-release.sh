#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
# Build the release archive and SHA256SUMS into dist/.
#
#   tools/build-release.sh <version>
#
# One archive serves arm64 and amd64: it holds both static binaries (bin/x86_64/scapegoat and
# bin/aarch64/scapegoat, built first by tools/build-bin.sh), bin/scapegoat, which runs the one
# for the machine, and deploy/ with install.sh. VERSION must equal <version>.
set -euo pipefail
v="${1:?usage: build-release.sh <version>}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$(cat "$repo/VERSION")" = "$v" ] || { echo "VERSION is $(cat "$repo/VERSION"), not $v" >&2; exit 1; }
dist="$repo/dist"
rm -rf "$dist"
mkdir -p "$dist"
name="scapegoat-$v"
for a in x86_64 aarch64; do
    [ -x "$repo/bin/$a/scapegoat" ] || { echo "bin/$a/scapegoat is missing: tools/build-bin.sh $a" >&2; exit 1; }
done
# git archive: exactly the committed tree, with a fixed mtime from the commit.
git -C "$repo" archive --format=tar --prefix="$name/" HEAD \
    bin deploy docs profiles LICENSE NOTICE README.md SECURITY.md VERSION CHANGELOG.md \
    > "$dist/$name.tar"
# The binaries are built, not committed; they go in with the commit's time and root ownership.
tar -C "$repo" --append -f "$dist/$name.tar" --transform "s,^,$name/," --owner=0 --group=0 --numeric-owner \
    --mtime="@$(git -C "$repo" log -1 --format=%ct)" --mode=0755 bin/x86_64/scapegoat bin/aarch64/scapegoat
gzip -n -9 "$dist/$name.tar"
(cd "$dist" && sha256sum "$name.tar.gz" > SHA256SUMS)
cat "$dist/SHA256SUMS"
