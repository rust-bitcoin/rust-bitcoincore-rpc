#!/bin/sh

TESTDIR=/tmp/rust_bitcoincore_rpc_test

rm -rf ${TESTDIR}
mkdir -p ${TESTDIR}/1 ${TESTDIR}/2

# To kill any remaining open bitcoind.
killall -9 bitcoind

bitcoind -regtest \
    -excessiveblocksize=1000000000 \
    -maxstackmemoryusageconsensus=200000000 \
    -minminingtxfee=0 \
    -datadir=${TESTDIR}/1 \
    -port=12348 \
    -server=0 \
    -printtoconsole=0 &
PID1=$!

# Make sure it's listening on its p2p port.
sleep 3

bitcoind -regtest  \
    -excessiveblocksize=1000000000 \
    -maxstackmemoryusageconsensus=200000000 \
    -minminingtxfee=0 \
    -datadir=${TESTDIR}/2 \
    -connect=127.0.0.1:12348 \
    -rpcport=12349 \
    -server=1 \
    -txindex=1 \
    -printtoconsole=0 &
PID2=$!

# Let it connect to the other node.
sleep 5

RPC_URL=http://localhost:12349 \
    RPC_COOKIE=${TESTDIR}/2/regtest/.cookie \
    TESTDIR=${TESTDIR} \
    RUST_BACKTRACE=1 \
    cargo run

RESULT=$?

kill -9 $PID1 $PID2

exit $RESULT
