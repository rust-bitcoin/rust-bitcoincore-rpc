// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Rust Client for Bitcoin Core API
//!
//! This is a client library for the Bitcoin Core JSON-RPC API.
//!

#![crate_name = "bitcoincore_rpc"]
#![crate_type = "rlib"]

#[macro_use]
extern crate log;
extern crate bitcoin;
extern crate bitcoin_amount;
extern crate bitcoin_hashes;
extern crate hex;
extern crate jsonrpc;
extern crate num_bigint;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;

pub extern crate bitcoincore_rpc_json;
pub use bitcoincore_rpc_json as json;
pub use bitcoincore_rpc_json::getters::*;

mod batch;
mod client;
mod error;
mod queryable;
mod util;

pub use batch::*;
pub use client::*;
pub use error::Error;
pub use queryable::*;

use bitcoin::{Address, Block, BlockHeader, Transaction};
use bitcoin_amount::Amount;
use bitcoin_hashes::sha256d;
use num_bigint::BigUint;
use secp256k1::Signature;
use std::collections::HashMap;

use util::*;

/// Crate-specific Result type, shorthand for `std::result::Result` with our
/// crate-specific Error type;
pub type Result<T> = ::std::result::Result<T, Error>;

pub trait RpcApi: Sized {
    /// Call a `cmd` rpc with given `args` list
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T>;

    /// Query an object implementing `Querable` type
    fn get_by_id<T: queryable::Queryable<Self>>(
        &self,
        id: &<T as queryable::Queryable<Self>>::Id,
    ) -> Result<T> {
        T::query(&self, &id)
    }

    fn add_multisig_address(
        &self,
        nrequired: usize,
        keys: Vec<json::PubKeyOrAddress>,
        label: Option<&str>,
        address_type: Option<json::AddressType>,
    ) -> Result<json::AddMultiSigAddressResult> {
        let mut args = [
            into_json(nrequired)?,
            into_json(keys)?,
            opt_into_json(label)?,
            opt_into_json(address_type)?,
        ];
        self.call("addmultisigaddress", handle_defaults(&mut args, &[into_json("")?, null()]))
    }

    fn backup_wallet(&self, destination: Option<&str>) -> Result<()> {
        let mut args = [opt_into_json(destination)?];
        self.call("backupwallet", handle_defaults(&mut args, &[null()]))
    }

    // TODO(stevenroose) use Privkey type
    // TODO(dpc): should we convert? Or maybe we should have two methods?
    //            just like with `getrawtransaction` it is sometimes useful
    //            to just get the string dump, without converting it into
    //            `bitcoin` type; Maybe we should made it `Queryable` by
    //            `Address`!
    fn dump_priv_key(&self, address: &Address) -> Result<String> {
        self.call("dumpprivkey", &[into_json(address)?])
    }

    fn encrypt_wallet(&self, passphrase: &str) -> Result<()> {
        self.call("encryptwallet", &[into_json(passphrase)?])
    }

    //TODO(stevenroose) verify if return type works
    fn get_difficulty(&self) -> Result<BigUint> {
        self.call("getdifficulty", &[])
    }

    fn get_connection_count(&self) -> Result<usize> {
        self.call("getconnectioncount", &[])
    }

    fn get_block(&self, hash: &sha256d::Hash) -> Result<Block> {
        let hex: String = self.call("getblock", &[into_json(hash)?, 0.into()])?;
        let bytes = hex::decode(hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    fn get_block_hex(&self, hash: &sha256d::Hash) -> Result<String> {
        self.call("getblock", &[into_json(hash)?, 0.into()])
    }

    fn get_block_info(&self, hash: &sha256d::Hash) -> Result<json::GetBlockResult> {
        self.call("getblock", &[into_json(hash)?, 1.into()])
    }
    //TODO(stevenroose) add getblock_txs

    fn get_block_header_raw(&self, hash: &sha256d::Hash) -> Result<BlockHeader> {
        let hex: String = self.call("getblockheader", &[into_json(hash)?, false.into()])?;
        let bytes = hex::decode(hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    fn get_block_header_verbose(&self, hash: &sha256d::Hash) -> Result<json::GetBlockHeaderResult> {
        self.call("getblockheader", &[into_json(hash)?, true.into()])
    }

    fn get_mining_info(&self) -> Result<json::GetMiningInfoResult> {
        self.call("getmininginfo", &[])
    }

    /// Returns a data structure containing various state info regarding
    /// blockchain processing.
    fn get_blockchain_info(&self) -> Result<json::GetBlockchainInfoResult> {
        self.call("getblockchaininfo", &[])
    }

    /// Returns the numbers of block in the longest chain.
    fn get_block_count(&self) -> Result<u64> {
        self.call("getblockcount", &[])
    }

    /// Returns the hash of the best (tip) block in the longest blockchain.
    fn get_best_block_hash(&self) -> Result<sha256d::Hash> {
        self.call("getbestblockhash", &[])
    }

    /// Get block hash at a given height
    fn get_block_hash(&self, height: u64) -> Result<sha256d::Hash> {
        self.call("getblockhash", &[height.into()])
    }

    fn get_raw_transaction(
        &self,
        txid: &sha256d::Hash,
        block_hash: Option<&sha256d::Hash>,
    ) -> Result<Transaction> {
        let mut args = [into_json(txid)?, into_json(false)?, opt_into_json(block_hash)?];
        let hex: String = self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))?;
        let bytes = hex::decode(hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    fn get_raw_transaction_hex(
        &self,
        txid: &sha256d::Hash,
        block_hash: Option<&sha256d::Hash>,
    ) -> Result<String> {
        let mut args = [into_json(txid)?, into_json(false)?, opt_into_json(block_hash)?];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))
    }

    fn get_raw_transaction_verbose(
        &self,
        txid: &sha256d::Hash,
        block_hash: Option<&sha256d::Hash>,
    ) -> Result<json::GetRawTransactionResult> {
        let mut args = [into_json(txid)?, into_json(true)?, opt_into_json(block_hash)?];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))
    }

    fn get_received_by_address(&self, address: &Address, minconf: Option<u32>) -> Result<Amount> {
        let mut args = [into_json(address)?, opt_into_json(minconf)?];
        self.call("getreceivedbyaddress", handle_defaults(&mut args, &[null()]))
    }

    fn get_transaction(
        &self,
        txid: &sha256d::Hash,
        include_watchonly: Option<bool>,
    ) -> Result<json::GetTransactionResult> {
        let mut args = [into_json(txid)?, opt_into_json(include_watchonly)?];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))
    }

    fn get_tx_out(
        &self,
        txid: &sha256d::Hash,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<json::GetTxOutResult>> {
        let mut args = [into_json(txid)?, into_json(vout)?, opt_into_json(include_mempool)?];
        self.call("gettxout", handle_defaults(&mut args, &[null()]))
    }

    fn import_priv_key(
        &self,
        privkey: &str,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        let mut args = [into_json(privkey)?, into_json(label)?, opt_into_json(rescan)?];
        self.call("importprivkey", handle_defaults(&mut args, &[into_json("")?, null()]))
    }

    fn key_pool_refill(&self, new_size: Option<usize>) -> Result<()> {
        let mut args = [opt_into_json(new_size)?];
        self.call("keypoolrefill", handle_defaults(&mut args, &[null()]))
    }

    fn list_unspent(
        &self,
        minconf: Option<usize>,
        maxconf: Option<usize>,
        addresses: Option<Vec<&Address>>,
        include_unsafe: Option<bool>,
        query_options: Option<HashMap<&str, &str>>,
    ) -> Result<Vec<json::ListUnspentResult>> {
        let mut args = [
            opt_into_json(minconf)?,
            opt_into_json(maxconf)?,
            opt_into_json(addresses)?,
            opt_into_json(include_unsafe)?,
            opt_into_json(query_options)?,
        ];
        let defaults = [
            into_json(0)?,
            into_json(9999999)?,
            into_json::<&[Address]>(&[])?,
            into_json(true)?,
            null(),
        ];
        self.call("listunspent", handle_defaults(&mut args, &defaults))
    }

    fn create_raw_transaction_hex(
        &self,
        utxos: &[json::CreateRawTransactionInput],
        outs: Option<&HashMap<String, f64>>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<String> {
        let mut args = [
            into_json(utxos)?,
            opt_into_json(outs)?,
            opt_into_json(locktime)?,
            opt_into_json(replaceable)?,
        ];
        let defaults =
            [into_json::<&[json::CreateRawTransactionInput]>(&[])?, into_json(0i64)?, null()];
        self.call("createrawtransaction", handle_defaults(&mut args, &defaults))
    }

    fn create_raw_transaction(
        &self,
        utxos: &[json::CreateRawTransactionInput],
        outs: Option<&HashMap<String, f64>>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<Transaction> {
        let hex: String = self.create_raw_transaction_hex(utxos, outs, locktime, replaceable)?;
        let bytes = hex::decode(hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    fn sign_raw_transaction(
        &self,
        tx: json::HexBytes,
        utxos: Option<&[json::SignRawTransactionInput]>,
        private_keys: Option<&[&str]>,
        sighash_type: Option<json::SigHashType>,
    ) -> Result<json::SignRawTransactionResult> {
        let mut args = [
            into_json(tx)?,
            opt_into_json(utxos)?,
            opt_into_json(private_keys)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [
            into_json::<&[json::SignRawTransactionInput]>(&[])?,
            into_json::<&[&str]>(&[])?,
            null(),
        ];
        self.call("signrawtransaction", handle_defaults(&mut args, &defaults))
    }

    fn sign_raw_transaction_with_key(
        &self,
        tx: json::HexBytes,
        privkeys: &[&str],
        prevtxs: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<json::SigHashType>,
    ) -> Result<json::SignRawTransactionResult> {
        let mut args = [
            into_json(tx)?,
            into_json(privkeys)?,
            opt_into_json(prevtxs)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [into_json::<&[json::SignRawTransactionInput]>(&[])?, null()];
        self.call("signrawtransactionwithkey", handle_defaults(&mut args, &defaults))
    }

    fn test_mempool_accept(&self, rawtxs: &[&str]) -> Result<Vec<json::TestMempoolAccept>> {
        self.call("testmempoolaccept", &[into_json(rawtxs)?])
    }

    fn stop(&self) -> Result<()> {
        self.call("stop", &[])
    }

    fn sign_raw_transaction_with_wallet(
        &self,
        tx: json::HexBytes,
        utxos: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<json::SigHashType>,
    ) -> Result<json::SignRawTransactionResult> {
        let mut args = [into_json(tx)?, opt_into_json(utxos)?, opt_into_json(sighash_type)?];
        let defaults = [into_json::<&[json::SignRawTransactionInput]>(&[])?, null()];
        self.call("signrawtransactionwithwallet", handle_defaults(&mut args, &defaults))
    }

    fn verify_message(
        &self,
        address: &Address,
        signature: &Signature,
        message: &str,
    ) -> Result<bool> {
        let args = [into_json(address)?, into_json(signature)?, into_json(message)?];
        self.call("verifymessage", &args)
    }

    /// Generate new address under own control
    ///
    /// If 'account' is specified (DEPRECATED), it is added to the address book
    /// so payments received with the address will be credited to 'account'.
    fn get_new_address(
        &self,
        account: Option<&str>,
        address_type: Option<json::AddressType>,
    ) -> Result<String> {
        self.call("getnewaddress", &[opt_into_json(account)?, opt_into_json(address_type)?])
    }

    /// Mine `block_num` blocks and pay coinbase to `address`
    ///
    /// Returns hashes of the generated blocks
    fn generate_to_address(&self, block_num: u64, address: &str) -> Result<Vec<sha256d::Hash>> {
        self.call("generatetoaddress", &[block_num.into(), address.into()])
    }

    /// Mine up to block_num blocks immediately (before the RPC call returns)
    /// to an address in the wallet.
    fn generate(&self, block_num: u64, maxtries: Option<u64>) -> Result<Vec<sha256d::Hash>> {
        self.call("generate", &[block_num.into(), opt_into_json(maxtries)?])
    }

    /// Mark a block as invalid by `block_hash`
    fn invalidate_block(&self, block_hash: &sha256d::Hash) -> Result<()> {
        self.call("invalidateblock", &[into_json(block_hash)?])
    }

    fn send_to_address(
        &self,
        addr: &str,
        amount: f64,
        comment: Option<&str>,
        comment_to: Option<&str>,
        substract_fee: Option<bool>,
    ) -> Result<sha256d::Hash> {
        let mut args = [
            into_json(addr)?,
            into_json(amount)?,
            opt_into_json(comment)?,
            opt_into_json(comment_to)?,
            opt_into_json(substract_fee)?,
        ];
        self.call("sendtoaddress", handle_defaults(&mut args, &["".into(), "".into(), null()]))
    }
    /// Returns data about each connected network node as an array of
    /// [`PeerInfo`][]
    ///
    /// [`PeerInfo`]: net/struct.PeerInfo.html
    fn get_peer_info(&self) -> Result<Vec<json::GetPeerInfoResult>> {
        self.call("getpeerinfo", &[])
    }

    /// Requests that a ping be sent to all other nodes, to measure ping
    /// time.
    ///
    /// Results provided in `getpeerinfo`, `pingtime` and `pingwait` fields
    /// are decimal seconds.
    ///
    /// Ping command is handled in queue with all other commands, so it
    /// measures processing backlog, not just network ping.
    fn ping(&self) -> Result<()> {
        self.call("ping", &[])
    }

    fn send_raw_transaction(&self, tx: &str) -> Result<String> {
        self.call("sendrawtransaction", &[into_json(tx)?])
    }

    fn estimate_smartfee<E>(
        &self,
        conf_target: u16,
        estimate_mode: Option<json::EstimateMode>,
    ) -> Result<json::EstimateSmartFeeResult> {
        let mut args = [into_json(conf_target)?, opt_into_json(estimate_mode)?];
        self.call("estimatesmartfee", handle_defaults(&mut args, &[null()]))
    }

    /// Waits for a specific new block and returns useful info about it.
    /// Returns the current block on timeout or exit.
    ///
    /// # Arguments
    ///
    /// 1. `timeout`: Time in milliseconds to wait for a response. 0
    /// indicates no timeout.
    fn wait_for_new_block(&self, timeout: u64) -> Result<json::BlockRef> {
        self.call("waitfornewblock", &[into_json(timeout)?])
    }

    /// Waits for a specific new block and returns useful info about it.
    /// Returns the current block on timeout or exit.
    ///
    /// # Arguments
    ///
    /// 1. `blockhash`: Block hash to wait for.
    /// 2. `timeout`: Time in milliseconds to wait for a response. 0
    /// indicates no timeout.
    fn wait_for_block(&self, blockhash: &sha256d::Hash, timeout: u64) -> Result<json::BlockRef> {
        let args = [into_json(blockhash)?, into_json(timeout)?];
        self.call("waitforblock", &args)
    }
}
