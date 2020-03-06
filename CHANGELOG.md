
# v0.9.1

- Add `wallet_create_funded_psbt`
- Add `get_descriptor_info`
- Add `combine_psbt`
- Add `derive_addresses`
- Add `finalize_psbt`
- Add `rescan_blockchain`

# v0.7.0

- use `bitcoin::PublicKey` instead of `secp256k1::PublicKey`
- fix get_mining_info result issue
- fix test_mempool_accept issue
- fix get_transaction result issues
- fix bug in fund_raw_transaction
- add list_transactions
- add get_raw_mempool
- add reconsider_block
- add import_multi
- add import_public_key
- add set_label
- add lock_unspent
- add unlock_unspent
- add create_wallet
- add load_wallet
- add unload_wallet
- increased log level for requests to debug

# v0.6.0

- polish Auth to use owned Strings
- fix using Amount type and Address types where needed
- use references of sha256d::Hashes instead of owned/copied

# v0.5.1

- add get_tx_out_proof
- add import_address
- add list_received_by_address

# v0.5.0

- add support for cookie authentication
- add fund_raw_transaction command
- deprecate sign_raw_transaction
- use PrivateKey type for calls instead of string
- fix for sign_raw_transaction
- use 32-bit integers for confirmations, signed when needed

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
