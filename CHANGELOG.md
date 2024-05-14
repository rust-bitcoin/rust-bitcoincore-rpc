# 0.19.0

- Change MSRV from 1.48.0 to 1.56.1 [#334](https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/334)
- Implement `verifymessage` RCP call (and add "verifymessage" feature)
   - [#326](https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/326)
   - [#343](https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/343)
- Upgrade `bitcoin` dependency to `v0.32.0` [#337](https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/337)
- Upgrade `jsonrpc` dependency to `v0.18.0` [#339](https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/339)
- Use `jsonrpc` "minreq_http" feature [#341](https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/341)
- Add "rand" feature [#342](https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/342)

# 0.18.0

- MSRV changed from 1.41.1 to 1.48.0
- Use `bitcoin::Network` in `GetBlockchainInfoResult `.
- Make checksum optional in `GetDescriptorInfoResult`.
- Make `getmempoolinfo` compatible with supported RPC versions.

# 0.17.0

- add `list_wallet_dir` rpc
- add `join_psbt` rpc
- add `get_raw_change_address` rpc
- add `create_psbt` rpc
- add `combine_raw_transaction` rpc
- add `decode_raw_transaction` rpc
- add `import_descriptors` rpc
- add `get_mempool_info` rpc
- add `get_index_info` rpc
- change return type of `unload_wallet`
- update `jsonrpc` dependency to 0.14.0
- update `bitcoin` dependency to 0.30.0

# 0.16.0

- MSRV changed from 1.29 to 1.41.1
- bump bitcoin crate version to 0.29.0
- moved to Rust edition 2018
- make get_tx_out_set_info compatible with v22+
- add `submit_block`, `submit_block_bytes`, `submit_block_hex`

# 0.15.0

- bump bitcoin crate version to 0.28.0
- add `get_block_stats`
- add `add_node`
- add `remove_node`
- add `onetry_node`
- add `disconnect_node`
- add `disconnect_node_by_id`
- add `get_added_node_info`
- add `get_node_addresses`
- add `list_banned`
- add `clear_banned`
- add `add_ban`
- add `remove_ban`
- make `Auth::get_user_pass` public
- add `ScriptPubkeyType::witness_v1_taproot`

# 0.14.0

- add `wallet_conflicts` field in `WalletTxInfo`
- add `get_chain_tips`
- add `get_block_template`
- implement `From<u64>` and `From<Option<u64>>` for `ImportMultiRescanSince`
- bump rust-bitcoin dependency to 0.27
- bump json-rpc dependency to 0.12.0
- remove dependency on `hex`

# 0.13.0

- add `wallet_process_psbt`
- add `unlock_unspent_all`
- compatibility with Bitcoin Core v0.21
- bump rust-bitcoin dependency to 0.26
- implement Deserialize for ImportMultiRescanSince
- some fixes for some negative confirmation values

# 0.12.0

- bump `bitcoin` dependency to version `0.25`, increasing our MSRV to `1.29.0`
- test against `bitcoind` `0.20.0` and `0.20.1`
- add `get_balances`
- add `get_mempool_entry`
- add `list_since_block`
- add `get_mempool_entry`
- add `list_since_block`
- add `uptime`
- add `get_network_hash_ps`
- add `get_tx_out_set_info`
- add `get_net_totals`
- partially implement `scantxoutset`
- extend `create_wallet` and related APIs
- extend `GetWalletInfoResult`
- extend `WalletTxInfo`
- extend testsuite
- fix `GetPeerInfoResult`
- fix `GetNetworkInfoResult`
- fix `GetTransactionResultDetailCategory`
- fix `GetMempoolEntryResult` for bitcoind prior to `0.19.0`
- fix `GetBlockResult` and `GetBlockHeaderResult`

# 0.11.0

- fix `minimum_sum_amount` field name in `ListUnspentQueryOptions`
- add missing "orphan" variant for `GetTransactionResultDetailCategory`
- add `ImportMultiRescanSince` to support "now" for `importmulti`'s
  `timestamp` parameter
- rename logging target to `bitcoincore_rpc` instead of `bitcoincore_rpc::client`
- other logging improvements

# 0.10.0

- rename `dump_priv_key` -> `dump_private_key` + change return type
- rename `get_block_header_xxx` methods to conform with `get_block_xxx` methods
- rename `get_raw_transaction_xxx` methods to conform with `get_block_xxx` methods
- rename `GetBlockHeaderResult` fields
- rename `GetMiningInfoResult` fields
- represent difficulty values as `f64` instead of `BigUint`
- fix `get_peer_info`
- fix `get_transaction`
- fix `get_balance`
- fix `get_blockchain_info` and make compatible with both 0.18 and 0.19
- fix `get_address_info`
- fix `send_to_address`
- fix `estimate_smart_fee`
- fix `import_private_key`
- fix `list_received_by_address`
- fix `import_address`
- fix `finalize_psbt`
- fix `fund_raw_transaction`
- fix `test_mempool_accept`
- fix `stop`
- fix `rescan_blockchain`
- add `import_address_script`
- add `get_network_info`
- add `version`
- add `Error::UnexpectedStructure`
- add `GetTransactionResultDetailCategory::Immature`
- make `list_unspent` more ergonomic
- made all exported enum types implement `Copy`
- export `jsonrpc` dependency.
- remove `num_bigint` dependency

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
