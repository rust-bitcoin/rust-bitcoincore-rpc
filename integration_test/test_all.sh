
set -xe

# Integration test.
if [ -n "$BSVVERSION" ]; then
    wget https://download.bitcoinsv.io/bitcoinsv/$BSVVERSION/bitcoin-sv-$BSVVERSION-x86_64-linux-gnu.tar.gz
    tar -xzvf bitcoin-sv-$BSVVERSION-x86_64-linux-gnu.tar.gz
    export PATH=$PATH:$(pwd)/bitcoin-sv-$BSVVERSION/bin
    cd integration_test
    ./run.sh
    exit 0
else
  # Regular build/unit test.
  cargo build --verbose
  cargo test --verbose
  cargo build --verbose --examples
fi
