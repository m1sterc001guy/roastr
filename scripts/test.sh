#!/usr/bin/env bash
# Sets up environment variables for devimint-based tests

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
source ./scripts/build.sh

cargo test -p fedimint-starter-tests
