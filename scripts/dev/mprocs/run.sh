#!/usr/bin/env bash

set -euo pipefail

source scripts/_common.sh

ensure_in_dev_shell
build_workspace
add_target_dir_to_path

../fedimint/target-nix/debug/devimint --link-test-dir .../fedimint/target/devimint "$@" dev-fed --exec bash -c 'mprocs -c misc/mprocs.yaml 2>$FM_LOGS_DIR/devimint-outer.log'
