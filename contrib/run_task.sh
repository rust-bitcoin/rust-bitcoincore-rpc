#!/usr/bin/env bash
#
# Run CI task, called by the `rust.yml` GitHub action.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
MSRV="1.56.1"

usage() {
    cat <<EOF
Usage: 

    ./run_task.sh TASK

TASK
  - stable	    Run stable toolchain tests.
  - nightly    	    Run nightly toolchain tests.
  - msrv            Run MSRV toolchain tests.
  - fmt             Run the formatter (rustfmt).
  - integration     Run integration test for specific Bitcoin Core version.

    ./run_task.sh integration BITCOIN_CORE_VERSION [DOWNLOAD_CORE]

Example
    ./run_task.sh integration          # Runs integration tests against bitcoind from your path.
    ./run_task.sh integration 0.21.0   # Downloads Core version 0.21.0 and runs integration tests againts it. 

EOF
}

# Make all cargo invocations verbose.
export CARGO_TERM_VERBOSE=true

main() {
    local task="${1:-usage}"
    local bitcoin_version="${2:-none}"

    if [ "$task" = "usage" ] || [ "$task" = "-h" ] || [ "$task" = "--help" ]; then
        usage
        exit 0
    fi

    check_required_commands

    cargo --version
    rustc --version
    /usr/bin/env bash --version
    locale
    env

    case $task in
	stable)
            build_and_test "+stable"
            ;;

	nightly)
            build_and_test "+nightly"
            ;;

	msrv)
            do_msrv_pins
            build_and_test "+$MSRV"
            ;;

        fmt)
            do_fmt
            ;;

        integration)
            integration "$bitcoin_version"
            ;;

        *)
            echo ""
            usage
            err "Error: unknown task $task"
            ;;
    esac
}

# Build and test workspace.
build_and_test() {
    local toolchain="$1"

    for crate in json client integration_test; do
        pushd "$REPO_DIR/$crate" > /dev/null;

        cargo "$toolchain" build
        cargo "$toolchain" test

        popd > /dev/null
    done
}

# Pin dependencies to get the MSRV build to work.
do_msrv_pins() {
    cargo update -p tempfile --precise 3.6.0
    cargo update -p cc --precise 1.0.79
    cargo update -p log --precise 0.4.18
    cargo update -p serde_json --precise 1.0.96
    cargo update -p serde --precise 1.0.156
}

# Check the workspace formatting.
do_fmt() {
    cargo +stable fmt --all --check
}

# Pulls down Bitcoin Core binary and runs the integration tests.
integration() {
    local core_version="$1"

    cd "$REPO_DIR"

    if [ "$core_version" != "none" ]; then
        wget "https://bitcoincore.org/bin/bitcoin-core-$bitcoin_version/bitcoin-$bitcoin_version-x86_64-linux-gnu.tar.gz"
        tar -xzvf "bitcoin-$bitcoin_version-x86_64-linux-gnu.tar.gz"
        export PATH=$PATH:"$REPO_DIR/bitcoin-$bitcoin_version/bin"
    fi

    need_cmd "bitcoind"

    cd "$REPO_DIR/integration_test"
    ./run.sh
}

# Check all the commands we use are present in the current environment.
check_required_commands() {
    need_cmd cargo
    need_cmd rustc
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1
    then err "need '$1' (command not found)"
    fi
}

err() {
    echo "$1" >&2
    exit 1
}

#
# Main script
#
main "$@"
exit 0
