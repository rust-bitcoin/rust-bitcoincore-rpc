#!/bin/bash

set -xe

# Integration test.
if [ -n "$BSVVERSION" ]; then
    if [ ! -d "/bitcoin-sv-$BSVVERSION/bin"]; then
      if [ ! -f "bitcoin-sv-$BSVVERSION-x86_64-linux-gnu.tar.gz"]; then
        wget -nv https://download.bitcoinsv.io/bitcoinsv/$BSVVERSION/bitcoin-sv-$BSVVERSION-x86_64-linux-gnu.tar.gz
      fi
      tar -xzvf bitcoin-sv-$BSVVERSION-x86_64-linux-gnu.tar.gz
    fi
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
