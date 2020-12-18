
set -xe

# Just echo all the relevant env vars to help debug Travis.
echo "TRAVIS_RUST_VERSION: \"$TRAVIS_RUST_VERSION\""
echo "RUSTFMTCHECK: \"$RUSTFMTCHECK\""
echo "BITCOINVERSION: \"$BITCOINVERSION\""
echo "PATH: \"$PATH\""


# Pin dependencies for Rust v1.29
if [ "$TRAVIS_RUST_VERSION" = "1.29.0" ]; then
    cargo generate-lockfile --verbose
    cargo update --verbose --package "cc" --precise "1.0.41"
    cargo update --verbose --package "cfg-if" --precise "0.1.9"
    cargo update --verbose --package "serde_json" --precise "1.0.39"
    cargo update --verbose --package "serde" --precise "1.0.98"
    cargo update --verbose --package "serde_derive" --precise "1.0.98"
fi

if [ -n "$RUSTFMTCHECK" ]; then
  rustup component add rustfmt
  cargo fmt --all -- --check
fi

# Integration test.
if [ -n "$BITCOINVERSION" ]; then
    wget https://bitcoincore.org/bin/bitcoin-core-$BITCOINVERSION/bitcoin-$BITCOINVERSION-x86_64-linux-gnu.tar.gz
    tar -xzvf bitcoin-$BITCOINVERSION-x86_64-linux-gnu.tar.gz
    export PATH=$PATH:$(pwd)/bitcoin-$BITCOINVERSION/bin
    cd integration_test
    ./run.sh
    exit 0
fi

# Regular build/unit test.
cargo build --verbose
cargo test --verbose
cargo build --verbose --examples
