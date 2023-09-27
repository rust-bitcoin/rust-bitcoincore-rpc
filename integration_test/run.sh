#!/bin/sh

TESTDIR=/tmp/rust_bitcoincore_rpc_test

rm -rf ${TESTDIR}
mkdir -p ${TESTDIR}/1 ${TESTDIR}/2

docker stop dashcore-rpc-test-node
docker rm dashcore-rpc-test-node
docker volume rm dashcore-rpc-test-data

docker volume create --name=dashcore-rpc-test-data

DASH_CONF_PATH=$PWD/dash.conf

docker run --name=dashcore-rpc-test-node -d \
      -v $DASH_CONF_PATH:/home/dash/dash.conf \
      -v dashcore-rpc-test-data:/home/dash \
     -p 9999:9999 \
     -p 127.0.0.1:9998:9998 \
     dashpay/dashd:20.0.0-alpha.10 \
     dashd -conf=/home/dash/dash.conf -datadir=/home/dash

#
## Make sure it's listening on its p2p port.
sleep 3
#
#BLOCKFILTERARG=""
#if bitcoind -version | grep -q "v0\.\(19\|2\)"; then
#    BLOCKFILTERARG="-blockfilterindex=1"
#fi
#
#FALLBACKFEEARG=""
#if bitcoind -version | grep -q "v0\.2"; then
#    FALLBACKFEEARG="-fallbackfee=0.00001000"
#fi
#
#bitcoind -regtest $BLOCKFILTERARG $FALLBACKFEEARG \
#    -datadir=${TESTDIR}/2 \
#    -connect=127.0.0.1:12348 \
#    -rpcport=12349 \
#    -server=1 \
#    -txindex=1 \
#    -printtoconsole=0 &
#PID2=$!
#
## Let it connect to the other node.
#sleep 5

RPC_USER=$(cat $DASH_CONF_PATH | grep rpcuser | awk -F= '{print $2}')
RPC_PASS=$(cat $DASH_CONF_PATH | grep rpcpassword | awk -F= '{print $2}')

RPC_URL=http://localhost:9998 \
    RPC_USER=$RPC_USER \
    RPC_PASS=$RPC_PASS \
    cargo run
#
RESULT=$?

docker stop dashcore-rpc-test-node
docker rm dashcore-rpc-test-node
docker volume rm dashcore-rpc-test-data

exit $RESULT
