
set -xe

MSRV="1\.48"

# Just echo all the relevant env vars to help debug Travis.
echo "RUSTFMTCHECK: \"$RUSTFMTCHECK\""
echo "BITCOINVERSION: \"$BITCOINVERSION\""
echo "PATH: \"$PATH\""

if [ -n "$RUSTFMTCHECK" ]; then
  rustup component add rustfmt
  cargo fmt --all -- --check
fi

# Test pinned versions (these are from rust-bitcoin pinning for 1.48).
if cargo --version | grep ${MSRV}; then
    cargo update -p tempfile --precise 3.3.0
    cargo update -p log --precise 0.4.18
    cargo update -p serde_json --precise 1.0.99
    cargo update -p serde --precise 1.0.156
    cargo update -p quote --precise 1.0.30
    cargo update -p proc-macro2 --precise 1.0.63
fi

# Integration test.
if [ -n "$BITCOINVERSION" ]; then
    wget https://bitcoincore.org/bin/bitcoin-core-$BITCOINVERSION/bitcoin-$BITCOINVERSION-x86_64-linux-gnu.tar.gz
    tar -xzvf bitcoin-$BITCOINVERSION-x86_64-linux-gnu.tar.gz
    export PATH=$PATH:$(pwd)/bitcoin-$BITCOINVERSION/bin
    cd integration_test
    ./run.sh
    exit 0
else
  # Regular build/unit test.
  cargo build --verbose
  cargo test --verbose
  cargo build --verbose --examples
fi
