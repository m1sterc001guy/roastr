#!/usr/bin/env bash

set -euo pipefail

source scripts/_common.sh

ensure_in_dev_shell
build_workspace
add_target_dir_to_path

export FM_REL_NOTES_ACK=0_4_xyz

devimint --link-test-dir ./target/devimint "$@" dev-fed --exec bash -c 'mprocs -c misc/mprocs.yaml 2>$FM_LOGS_DIR/devimint-outer.log'
