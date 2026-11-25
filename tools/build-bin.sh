#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
# Build the static scapegoat binary for this machine's architecture (or the one named)
# into bin/<arch>/scapegoat, where bin/scapegoat finds it.
#
#   tools/build-bin.sh            this machine's architecture
#   tools/build-bin.sh aarch64    another
#
# Needs rustup (the toolchain is pinned in rust-toolchain.toml). The crate is pure Rust, so
# the musl target links with the Rust toolchain's own linker (rust-lld) on any host.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
arch="${1:-$(uname -m)}"
case "$arch" in arm64) arch=aarch64 ;; esac
case "$arch" in x86_64|aarch64) ;; *) echo "unsupported architecture $arch" >&2; exit 2 ;; esac
target="$arch-unknown-linux-musl"
linker_var="CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')_LINKER"
rustup target add "$target" >/dev/null
env "$linker_var=rust-lld" cargo build --manifest-path "$repo/Cargo.toml" --release --locked --target "$target"
target_dir="${CARGO_TARGET_DIR:-$repo/target}"
mkdir -p "$repo/bin/$arch"
install -m 0755 "$target_dir/$target/release/scapegoat" "$repo/bin/$arch/scapegoat"
echo "built $repo/bin/$arch/scapegoat ($(wc -c < "$repo/bin/$arch/scapegoat") bytes)"
