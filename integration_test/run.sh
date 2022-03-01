#!/bin/sh

BITCOIND_PATH="${BITCOIND_PATH:-bitcoind}"
TESTDIR=/tmp/rust_bitcoincore_rpc_test

rm -rf ${TESTDIR}
mkdir -p ${TESTDIR}/1 ${TESTDIR}/2

# To kill any remaining open bitcoind.
killall -9 bitcoind

${BITCOIND_PATH} -regtest \
    -datadir=${TESTDIR}/1 \
    -port=12348 \
    -server=0 \
    -printtoconsole=0 &
PID1=$!

# Make sure it's listening on its p2p port.
sleep 3

BLOCKFILTERARG=""
if ${BITCOIND_PATH} -version | grep -q "v\(2\|0\.19\|0.2\)"; then
    BLOCKFILTERARG="-blockfilterindex=1"
fi

FALLBACKFEEARG=""
if ${BITCOIND_PATH} -version | grep -q "v\(2\|0\.2\)"; then
    FALLBACKFEEARG="-fallbackfee=0.00001000"
fi

${BITCOIND_PATH} -regtest $BLOCKFILTERARG $FALLBACKFEEARG \
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
    cargo run

RESULT=$?

kill -9 $PID1 $PID2

exit $RESULT
