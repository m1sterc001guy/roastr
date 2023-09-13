#!/usr/bin/env bash
# Verifies printing money via the dummy module

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
source ./scripts/build.sh

cargo test -p fedimint-starter-tests
