#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
toolchain=${FUZZ_TOOLCHAIN:-nightly-2026-09-25}
seconds=${FUZZ_SECONDS:-30}
seed=${FUZZ_SEED:-20260927}
if [[ $# -gt 1 || ! "$seconds" =~ ^[1-9][0-9]*$ || ${#seconds} -gt 3 || "$seconds" -gt 600 || ! "$seed" =~ ^[1-9][0-9]*$ || ${#seed} -gt 10 || "$seed" -gt 4294967295 ]]; then
    echo 'Use at most one target, FUZZ_SECONDS=1..600 and FUZZ_SEED=1..4294967295.' >&2
    exit 2
fi
targets=(uri_parser binary_selectors ecdsa_encoding)
if [[ $# -gt 0 ]]; then
    case $1 in uri_parser|binary_selectors|ecdsa_encoding) targets=("$1") ;;
        *) echo 'Unknown fuzz target' >&2; exit 2 ;; esac
fi
# Validate and fetch the committed graph before cargo-fuzz's offline build.
cargo +"$toolchain" fetch --manifest-path fuzz/Cargo.toml --locked
for target in "${targets[@]}"; do
    mkdir -p "fuzz/corpus/$target" "fuzz/artifacts/$target"
    cp -R "fuzz/seeds/$target/." "fuzz/corpus/$target/"
    CARGO_NET_OFFLINE=true cargo +"$toolchain" fuzz run "$target" "fuzz/corpus/$target" \
        --target-dir "${CARGO_TARGET_DIR:-$PWD/fuzz/target}" -- \
        "-max_total_time=$seconds" "-seed=$seed" -max_len=4096 -timeout=5 \
        -rss_limit_mb=1024 -print_final_stats=1 "-artifact_prefix=fuzz/artifacts/$target/"
done
