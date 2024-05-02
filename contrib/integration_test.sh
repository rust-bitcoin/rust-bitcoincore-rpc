#!/usr/bin/env bash
#
# Run the integration test optionally downloading Bitcoin Core binary if BITCOINVERSION is set.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

# Make all cargo invocations verbose.
export CARGO_TERM_VERBOSE=true

main() {
    # If a specific version of Bitcoin Core is set then download the binary.
    if [ -n "${BITCOINVERSION+x}" ]; then
        download_binary
    fi

    need_cmd bitcoind

    cd integration_test
    ./run.sh
}

download_binary() {
    wget https://bitcoincore.org/bin/bitcoin-core-$BITCOINVERSION/bitcoin-$BITCOINVERSION-x86_64-linux-gnu.tar.gz
    tar -xzvf bitcoin-$BITCOINVERSION-x86_64-linux-gnu.tar.gz
    export PATH=$PATH:$(pwd)/bitcoin-$BITCOINVERSION/bin
}

err() {
    echo "$1" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1
    then err "need '$1' (command not found)"
    fi
}

#
# Main script
#
main "$@"
exit 0
