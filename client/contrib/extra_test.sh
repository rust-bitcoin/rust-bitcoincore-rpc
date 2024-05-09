#!/usr/bin/env bash

set -euox pipefail

# Currently there are two problems with the examples in this repo in relation to the `test_vas.sh` script.
#
# 1. `retry_client` cannot be run from `run_task.sh` because the `EXAMPLES` var
#    expects a feature and the `client` crate has no features, not even "default".
# 2. `test_against_node` is not meant to be run.
#
# Therefore we just build the examples.
cargo build --verbose --examples
