
# v0.4.0

- add RawTx trait for commands that take raw transactions
- update jsonrpc dependency to v0.11.0
- fix for create_raw_transaction
- fix for send_to_address
- fix for get_new_address
- fix for get_tx_out
- fix for get_raw_transaction_verbose
- use `secp256k1::SecretKey` type in API

# v0.3.0

- removed the GetTransaction and GetScript traits
    (those methods are now directly implemented on types)
- introduce RpcApi trait
- use bitcoin_hashes library
- add signrawtransactionwithkey command
- add testmempoolaccept command
- add generate command
- improve hexadecimal byte value representation
- bugfix getrawtransaction (support coinbase txs)
- update rust-bitcoin dependency v0.16.0 -> v0.18.0
- add RetryClient example

# v0.2.0

- add send_to_address command
- add create_raw_transaction command
- Client methods take self without mut
