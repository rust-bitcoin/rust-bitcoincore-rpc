#!/bin/sh

TESTDIR=/tmp/rust_bitcoincore_rpc_test

if bitcoind -version | grep -q "v22"; then
    echo "Starting two bitcoind v22 instances"
else
    echo "Currently tests are intended for Bitcoin Core v22"
    exit 1
fi

rm -rf ${TESTDIR}
mkdir -p ${TESTDIR}/1 ${TESTDIR}/2

bitcoind -regtest \
    -datadir=${TESTDIR}/1 \
    -port=12348 \
    -server=0 \
    -printtoconsole=0 &
PID1=$!

# Make sure it's listening on its p2p port.
sleep 1

bitcoind -regtest \
    -datadir=${TESTDIR}/2 \
    -connect=127.0.0.1:12348 \
    -rpcport=12349 \
    -rpcuser=user \
    -rpcpassword=password \
    -server=1 \
    -txindex=1 \
    -printtoconsole=0 \
    -zmqpubrawblock=tcp://0.0.0.0:28332 \
    -zmqpubrawtx=tcp://0.0.0.0:28333 &
PID2=$!

# Let it connect to the other node.
sleep 1

echo "Two connected bitcoind instances running, hit port 12349"

# RPC_URL=http://localhost:12349 \
#     RPC_COOKIE=${TESTDIR}/2/regtest/.cookie \
#     TESTDIR=${TESTDIR} \
#     cargo run

# RESULT=$?

# kill -9 $PID1 $PID2

# exit $RESULT
