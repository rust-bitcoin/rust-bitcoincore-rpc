use std::result;

use jsonrpc;
use serde_json;

use bitcoin::util::hash::Sha256dHash;
use bitcoin::{Address, Block, BlockHeader, Transaction};
use bitcoin_amount::Amount;
use log::Level::Trace;
use num_bigint::BigUint;
use secp256k1::Signature;
use std::collections::HashMap;

use error::*;
use json;
use queryable;

/// Crate-specific Result type, shorthand for `std::result::Result` with our
/// crate-specific Error type;
pub type Result<T> = result::Result<T, Error>;

/// Shorthand for converting a variable into a serde_json::Value.
fn into_json<T>(val: T) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    Ok(serde_json::to_value(val)?)
}

/// Shorthand for converting an Option into an Option<serde_json::Value>.
fn opt_into_json<T>(opt: Option<T>) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => Ok(into_json(val)?),
        None => Ok(serde_json::Value::Null),
    }
}

/// Shorthand for `serde_json::Value::Null`.
#[allow(unused)]
fn null() -> serde_json::Value {
    serde_json::Value::Null
}

/// Handle default values in the argument list
///
/// Substitute `Value::Null`s with corresponding values from `defaults` table,
/// except when they are trailing, in which case just skip them altogether
/// in returned list.
///
/// Note, that `defaults` corresponds to the last elements of `args`.
///
/// ```norust
/// arg1 arg2 arg3 arg4
///           def1 def2
/// ```
///
/// Elements of `args` without corresponding `defaults` value, won't
/// be substituted, because they are required.
fn handle_defaults<'a, 'b>(
    args: &'a mut [serde_json::Value],
    defaults: &'b [serde_json::Value],
) -> &'a [serde_json::Value] {
    assert!(args.len() >= defaults.len());

    // Pass over the optional arguments in backwards order, filling in defaults after the first
    // non-null optional argument has been observed.
    let mut first_non_null_optional_idx = None;
    for i in 0..defaults.len() {
        let args_i = args.len() - 1 - i;
        let defaults_i = defaults.len() - 1 - i;
        if args[args_i] == serde_json::Value::Null {
            if first_non_null_optional_idx.is_some() {
                if defaults[defaults_i] == serde_json::Value::Null {
                    panic!("Missing `default` for argument idx {}", args_i);
                }
                args[args_i] = defaults[defaults_i].clone();
            }
        } else {
            if first_non_null_optional_idx.is_none() {
                first_non_null_optional_idx = Some(args_i);
            }
        }
    }

    let required_num = args.len() - defaults.len();

    if let Some(i) = first_non_null_optional_idx {
        &args[..=i]
    } else {
        &args[..required_num]
    }
}

/// Client implements a JSON-RPC client for the Bitcoin Core daemon or compatible APIs.
pub struct Client {
    client: jsonrpc::client::Client,
}

impl Client {
    /// Creates a client to a bitcoind JSON-RPC server.
    pub fn new(url: String, user: Option<String>, pass: Option<String>) -> Self {
        debug_assert!(pass.is_none() || user.is_some());

        Client {
            client: jsonrpc::client::Client::new(url, user, pass),
        }
    }

    /// Create a new Client.
    pub fn from_jsonrpc(client: jsonrpc::client::Client) -> Client {
        Client {
            client: client,
        }
    }

    /// Query an object implementing `Querable` type
    pub fn get_by_id<T: queryable::Queryable>(
        &mut self,
        id: &<T as queryable::Queryable>::Id,
    ) -> Result<T> {
        T::query(self, &id)
    }

    /// Call an `cmd` rpc with given `args` list
    pub(crate) fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &mut self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        // Get rid of to_owned after
        // https://github.com/apoelstra/rust-jsonrpc/pull/19
        // lands
        let req = self.client.build_request(cmd.to_owned(), args.to_owned());
        if log_enabled!(Trace) {
            trace!("JSON-RPC request: {}", serde_json::to_string(&req).unwrap());
        }

        let resp = self.client.send_request(&req).map_err(Error::from);
        if log_enabled!(Trace) && resp.is_ok() {
            let resp = resp.as_ref().unwrap();
            trace!("JSON-RPC response: {}", serde_json::to_string(resp).unwrap());
        }
        Ok(resp?.into_result()?)
    }

    pub fn add_multisig_address(
        &mut self,
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

    pub fn backup_wallet(&mut self, destination: Option<&str>) -> Result<()> {
        let mut args = [opt_into_json(destination)?];
        self.call("backupwallet", handle_defaults(&mut args, &[null()]))
    }

    // TODO(stevenroose) use Privkey type
    // TODO(dpc): should we convert? Or maybe we should have two methods?
    //            just like with `getrawtransaction` it is sometimes useful
    //            to just get the string dump, without converting it into
    //            `bitcoin` type; Maybe we should made it `Queryable` by
    //            `Address`!
    pub fn dump_priv_key(&mut self, address: &Address) -> Result<String> {
        self.call("dumpprivkey", &[into_json(address)?])
    }

    pub fn encrypt_wallet(&mut self, passphrase: &str) -> Result<()> {
        self.call("encryptwallet", &[into_json(passphrase)?])
    }

    //TODO(stevenroose) verify if return type works
    pub fn get_difficulty(&mut self) -> Result<BigUint> {
        self.call("getdifficulty", &[])
    }

    pub fn get_connection_count(&mut self) -> Result<usize> {
        self.call("getconnectioncount", &[])
    }

    pub fn get_block(&mut self, hash: &Sha256dHash) -> Result<Block> {
        let hex: String = self.call("getblock", &[into_json(hash)?, 0.into()])?;
        let bytes = hex::decode(hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    pub fn get_block_hex(&mut self, hash: &Sha256dHash) -> Result<String> {
        self.call("getblock", &[into_json(hash)?, 0.into()])
    }

    pub fn get_block_info(&mut self, hash: &Sha256dHash) -> Result<json::GetBlockResult> {
        self.call("getblock", &[into_json(hash)?, 1.into()])
    }
    //TODO(stevenroose) add getblock_txs

    pub fn get_block_header_raw(&mut self, hash: &Sha256dHash) -> Result<BlockHeader> {
        let hex: String = self.call("getblockheader", &[into_json(hash)?, false.into()])?;
        let bytes = hex::decode(hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    pub fn get_block_header_verbose(
        &mut self,
        hash: &Sha256dHash,
    ) -> Result<json::GetBlockHeaderResult> {
        self.call("getblockheader", &[into_json(hash)?, true.into()])
    }

    pub fn get_mining_info(&mut self) -> Result<json::GetMiningInfoResult> {
        self.call("getmininginfo", &[])
    }

    /// Returns a data structure containing various state info regarding
    /// blockchain processing.
    pub fn get_blockchain_info(&mut self) -> Result<json::GetBlockchainInfoResult> {
        self.call("getblockchaininfo", &[])
    }

    /// Returns the numbers of block in the longest chain.
    pub fn get_block_count(&mut self) -> Result<u64> {
        self.call("getblockcount", &[])
    }

    /// Returns the hash of the best (tip) block in the longest blockchain.
    pub fn get_best_block_hash(&mut self) -> Result<Sha256dHash> {
        self.call("getbestblockhash", &[])
    }

    /// Get block hash at a given height
    pub fn get_block_hash(&mut self, height: u64) -> Result<Sha256dHash> {
        self.call("getblockhash", &[height.into()])
    }

    pub fn get_raw_transaction(
        &mut self,
        txid: &Sha256dHash,
        block_hash: Option<&Sha256dHash>,
    ) -> Result<Transaction> {
        let mut args = [into_json(txid)?, into_json(false)?, opt_into_json(block_hash)?];
        let hex: String = self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))?;
        let bytes = hex::decode(hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    pub fn get_raw_transaction_hex(
        &mut self,
        txid: &Sha256dHash,
        block_hash: Option<&Sha256dHash>,
    ) -> Result<String> {
        let mut args = [into_json(txid)?, into_json(false)?, opt_into_json(block_hash)?];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))
    }

    pub fn get_raw_transaction_verbose(
        &mut self,
        txid: &Sha256dHash,
        block_hash: Option<&Sha256dHash>,
    ) -> Result<json::GetRawTransactionResult> {
        let mut args = [into_json(txid)?, into_json(true)?, opt_into_json(block_hash)?];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))
    }

    pub fn get_received_by_address(
        &mut self,
        address: &Address,
        minconf: Option<u32>,
    ) -> Result<Amount> {
        let mut args = [into_json(address)?, opt_into_json(minconf)?];
        self.call("getreceivedbyaddress", handle_defaults(&mut args, &[null()]))
    }

    pub fn get_transaction(
        &mut self,
        txid: &Sha256dHash,
        include_watchonly: Option<bool>,
    ) -> Result<json::GetTransactionResult> {
        let mut args = [into_json(txid)?, opt_into_json(include_watchonly)?];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))
    }

    pub fn get_tx_out(
        &mut self,
        txid: &Sha256dHash,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<json::GetTxOutResult> {
        let mut args = [into_json(txid)?, into_json(vout)?, opt_into_json(include_mempool)?];
        self.call("gettxout", handle_defaults(&mut args, &[null()]))
    }

    pub fn import_priv_key(
        &mut self,
        privkey: &str,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        let mut args = [into_json(privkey)?, into_json(label)?, opt_into_json(rescan)?];
        self.call("importprivkey", handle_defaults(&mut args, &[into_json("")?, null()]))
    }

    pub fn key_pool_refill(&mut self, new_size: Option<usize>) -> Result<()> {
        let mut args = [opt_into_json(new_size)?];
        self.call("keypoolrefill", handle_defaults(&mut args, &[null()]))
    }

    pub fn list_unspent(
        &mut self,
        minconf: Option<usize>,
        maxconf: Option<usize>,
        addresses: Option<Vec<&Address>>,
        include_unsafe: Option<bool>,
        query_options: Option<HashMap<String, String>>,
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

    pub fn sign_raw_transaction(
        &mut self,
        tx: json::HexBytes,
        utxos: Option<&[json::UTXO]>,
        private_keys: Option<&[String]>,
        sighash_type: Option<json::SigHashType>,
    ) -> Result<json::SignRawTransactionResult> {
        let mut args = [
            into_json(tx)?,
            opt_into_json(utxos)?,
            opt_into_json(private_keys)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [into_json::<&[json::UTXO]>(&[])?, into_json::<&[String]>(&[])?, null()];
        self.call("signrawtransaction", handle_defaults(&mut args, &defaults))
    }

    pub fn stop(&mut self) -> Result<()> {
        self.call("stop", &[])
    }

    pub fn sign_raw_transaction_with_wallet(
        &mut self,
        tx: json::HexBytes,
        utxos: Option<&[json::UTXO]>,
        sighash_type: Option<json::SigHashType>,
    ) -> Result<json::SignRawTransactionResult> {
        let mut args = [into_json(tx)?, opt_into_json(utxos)?, opt_into_json(sighash_type)?];
        let defaults = [into_json::<&[json::UTXO]>(&[])?, null()];
        self.call("signrawtransactionwithwallet", handle_defaults(&mut args, &defaults))
    }

    pub fn verify_message(
        &mut self,
        address: &Address,
        signature: &Signature,
        message: &str,
    ) -> Result<bool> {
        let args = [into_json(address)?, into_json(signature)?, into_json(message)?];
        self.call("verifymessage", &args)
    }

    /// Generate new address under own control
    pub fn get_new_address(&mut self, account: &str) -> Result<String> {
        self.call("getnewaddress", &[into_json(account)?])
    }

    /// Mine `block_num` blocks and pay coinbase to `address`
    ///
    /// Returns hashes of the generated blocks
    pub fn generate_to_address(
        &mut self,
        block_num: u64,
        address: &str,
    ) -> Result<Vec<Sha256dHash>> {
        self.call("generatetoaddress", &[block_num.into(), address.into()])
    }

    /// Mark a block as invalid by `block_hash`
    pub fn invalidate_block(&mut self, block_hash: &Sha256dHash) -> Result<()> {
        self.call("invalidateblock", &[into_json(block_hash)?])
    }

    /// Returns data about each connected network node as an array of
    /// [`PeerInfo`][]
    ///
    /// [`PeerInfo`]: net/struct.PeerInfo.html
    pub fn get_peer_info(&mut self) -> Result<Vec<json::GetPeerInfoResult>> {
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
    pub fn ping(&mut self) -> Result<()> {
        self.call("ping", &[])
    }

    pub fn send_raw_transaction(&mut self, tx: &str) -> Result<String> {
        self.call("sendrawtransaction", &[into_json(tx)?])
    }

    pub fn estimate_smartfee<E>(
        &mut self,
        conf_target: u16,
        estimate_mode: Option<json::EstimateMode>,
    ) -> Result<json::EstimateSmartFeeResult> {
        let mut args = [into_json(conf_target)?, opt_into_json(estimate_mode)?];
        let defaults = [null()];
        self.call("estimatesmartfee", handle_defaults(&mut args, &defaults))
    }

    /// Waits for a specific new block and returns useful info about it.
    /// Returns the current block on timeout or exit.
    ///
    /// # Arguments
    ///
    /// 1. `timeout`: Time in milliseconds to wait for a response. 0
    /// indicates no timeout.
    pub fn wait_for_new_block(&mut self, timeout: u64) -> Result<json::BlockRef> {
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
    pub fn wait_for_block(
        &mut self,
        blockhash: &Sha256dHash,
        timeout: u64,
    ) -> Result<json::BlockRef> {
        let args = [into_json(blockhash)?, into_json(timeout)?];
        self.call("waitforblock", &args)
    }
}

#[cfg(tests)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_defaults() -> Result<()> {
        {
            let mut args = [into_json(0)?, null(), null()];
            let defaults = [into_json(1)?, into_json(2)?];
            let res = [into_json(0)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [into_json(0)?, into_json(1)?, null()];
            let defaults = [into_json(2)?];
            let res = [into_json(0)?, into_json(1)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [into_json(0)?, null(), into_json(5)?];
            let defaults = [into_json(2)?, into_json(3)?];
            let res = [into_json(0)?, into_json(2)?, into_json(5)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [into_json(0)?, null(), into_json(5)?, null()];
            let defaults = [into_json(2)?, into_json(3)?, into_json(4)?];
            let res = [into_json(0)?, into_json(2)?, into_json(5)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [null(), null()];
            let defaults = [into_json(2)?, into_json(3)?];
            let res: [serde_json::Value; 0] = [];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [null(), into_json(1)?];
            let defaults = [];
            let res = [null(), into_json(1)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [];
            let defaults = [];
            let res: [serde_json::Value; 0] = [];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [into_json(0)?];
            let defaults = [into_json(2)?];
            let res = [into_json(0)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        Ok(())
    }
}
