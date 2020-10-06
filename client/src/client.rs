// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use std::collections::HashMap;
use std::fs::File;
use std::iter::FromIterator;
use std::path::PathBuf;
use std::sync::Arc;
use std::{fmt, result};

use crate::bitcoin;
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse};
use reqwest;
use serde;
use serde_json;

use async_trait::async_trait;
use base64;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::secp256k1::Signature;
use bitcoin::{
    Address, Amount, Block, BlockHeader, OutPoint, PrivateKey, PublicKey, Script, Transaction,
};
use log::Level::{Debug, Trace, Warn};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::error::*;
use crate::json;
use crate::queryable;

/// Crate-specific Result type, shorthand for `std::result::Result` with our
/// crate-specific Error type;
pub type Result<T> = result::Result<T, Error>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonOutPoint {
    pub txid: bitcoin::Txid,
    pub vout: u32,
}

impl From<OutPoint> for JsonOutPoint {
    fn from(o: OutPoint) -> JsonOutPoint {
        JsonOutPoint {
            txid: o.txid,
            vout: o.vout,
        }
    }
}

impl Into<OutPoint> for JsonOutPoint {
    fn into(self) -> OutPoint {
        OutPoint {
            txid: self.txid,
            vout: self.vout,
        }
    }
}

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
fn null() -> serde_json::Value {
    serde_json::Value::Null
}

/// Shorthand for an empty serde_json::Value array.
fn empty_arr() -> serde_json::Value {
    serde_json::Value::Array(vec![])
}

/// Shorthand for an empty serde_json object.
fn empty_obj() -> serde_json::Value {
    serde_json::Value::Object(Default::default())
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
        } else if first_non_null_optional_idx.is_none() {
            first_non_null_optional_idx = Some(args_i);
        }
    }

    let required_num = args.len() - defaults.len();

    if let Some(i) = first_non_null_optional_idx {
        &args[..i + 1]
    } else {
        &args[..required_num]
    }
}

/// Convert a possible-null result into an Option.
fn opt_result<T: for<'a> serde::de::Deserialize<'a>>(
    result: serde_json::Value,
) -> Result<Option<T>> {
    if result == serde_json::Value::Null {
        Ok(None)
    } else {
        Ok(serde_json::from_value(result)?)
    }
}

/// Used to pass raw txs into the API.
pub trait RawTx: Sized + Clone {
    fn raw_hex(self) -> String;
}

impl<'a> RawTx for &'a Transaction {
    fn raw_hex(self) -> String {
        bitcoin::consensus::encode::serialize(self).to_hex()
    }
}

impl<'a> RawTx for &'a [u8] {
    fn raw_hex(self) -> String {
        self.to_hex()
    }
}

impl<'a> RawTx for &'a Vec<u8> {
    fn raw_hex(self) -> String {
        self.to_hex()
    }
}

impl<'a> RawTx for &'a str {
    fn raw_hex(self) -> String {
        self.to_owned()
    }
}

impl RawTx for String {
    fn raw_hex(self) -> String {
        self
    }
}

/// The different authentication methods for the client.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum Auth {
    None,
    UserPass(String, String),
    CookieFile(PathBuf),
}

impl Auth {
    /// Convert into the arguments that jsonrpc::Client needs.
    fn get_user_pass(self) -> Result<(Option<String>, Option<String>)> {
        use std::io::Read;
        match self {
            Auth::None => Ok((None, None)),
            Auth::UserPass(u, p) => Ok((Some(u), Some(p))),
            Auth::CookieFile(path) => {
                let mut file = File::open(path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let mut split = contents.splitn(2, ":");
                Ok((
                    Some(split.next().ok_or(Error::InvalidCookieFile)?.into()),
                    Some(split.next().ok_or(Error::InvalidCookieFile)?.into()),
                ))
            }
        }
    }
}

#[async_trait]
pub trait RpcApi: Sized {
    /// Call a `cmd` rpc with given `args` list
    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T>;

    /// Query an object implementing `Querable` type
    async fn get_by_id<T: queryable::Queryable<Self>>(
        &self,
        id: &<T as queryable::Queryable<Self>>::Id,
    ) -> Result<T>
    where
        <T as queryable::Queryable<Self>>::Id: Sync,
    {
        T::query(&self, &id).await
    }

    async fn get_network_info(&self) -> Result<json::GetNetworkInfoResult> {
        self.call("getnetworkinfo", &[]).await
    }

    async fn version(&self) -> Result<usize> {
        #[derive(Deserialize)]
        struct Response {
            pub version: usize,
        }
        let res: Response = self.call("getnetworkinfo", &[]).await?;
        Ok(res.version)
    }

    async fn add_multisig_address<'a>(
        &self,
        nrequired: usize,
        keys: &'a [json::PubKeyOrAddress<'a>],
        label: Option<&str>,
        address_type: Option<json::AddressType>,
    ) -> Result<json::AddMultiSigAddressResult> {
        let mut args = [
            into_json(nrequired)?,
            into_json(keys)?,
            opt_into_json(label)?,
            opt_into_json(address_type)?,
        ];
        self.call(
            "addmultisigaddress",
            handle_defaults(&mut args, &[into_json("")?, null()]),
        )
        .await
    }

    async fn load_wallet(&self, wallet: &str) -> Result<json::LoadWalletResult> {
        self.call("loadwallet", &[wallet.into()]).await
    }

    async fn unload_wallet(&self, wallet: Option<&str>) -> Result<()> {
        let mut args = [opt_into_json(wallet)?];
        self.call("unloadwallet", handle_defaults(&mut args, &[null()]))
            .await
    }

    async fn create_wallet(
        &self,
        wallet: &str,
        disable_private_keys: Option<bool>,
        blank: Option<bool>,
        passphrase: Option<&str>,
        avoid_reuse: Option<bool>,
    ) -> Result<json::LoadWalletResult> {
        let mut args = [
            wallet.into(),
            opt_into_json(disable_private_keys)?,
            opt_into_json(blank)?,
            opt_into_json(passphrase)?,
            opt_into_json(avoid_reuse)?,
        ];
        self.call(
            "createwallet",
            handle_defaults(
                &mut args,
                &[false.into(), false.into(), into_json("")?, false.into()],
            ),
        )
        .await
    }

    async fn list_wallets(&self) -> Result<Vec<String>> {
        self.call("listwallets", &[]).await
    }

    async fn get_wallet_info(&self) -> Result<json::GetWalletInfoResult> {
        self.call("getwalletinfo", &[]).await
    }

    async fn backup_wallet(&self, destination: Option<&str>) -> Result<()> {
        let mut args = [opt_into_json(destination)?];
        self.call("backupwallet", handle_defaults(&mut args, &[null()]))
            .await
    }

    async fn dump_private_key(&self, address: &Address) -> Result<PrivateKey> {
        self.call("dumpprivkey", &[address.to_string().into()])
            .await
    }

    async fn encrypt_wallet(&self, passphrase: &str) -> Result<()> {
        self.call("encryptwallet", &[into_json(passphrase)?]).await
    }

    async fn get_difficulty(&self) -> Result<f64> {
        self.call("getdifficulty", &[]).await
    }

    async fn get_connection_count(&self) -> Result<usize> {
        self.call("getconnectioncount", &[]).await
    }

    async fn get_block(&self, hash: &bitcoin::BlockHash) -> Result<Block> {
        let hex: String = self.call("getblock", &[into_json(hash)?, 0.into()]).await?;
        let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    async fn get_block_hex(&self, hash: &bitcoin::BlockHash) -> Result<String> {
        self.call("getblock", &[into_json(hash)?, 0.into()]).await
    }

    async fn get_block_info(&self, hash: &bitcoin::BlockHash) -> Result<json::GetBlockResult> {
        self.call("getblock", &[into_json(hash)?, 1.into()]).await
    }
    //TODO(stevenroose) add getblock_txs

    async fn get_block_header(&self, hash: &bitcoin::BlockHash) -> Result<BlockHeader> {
        let hex: String = self
            .call("getblockheader", &[into_json(hash)?, false.into()])
            .await?;
        let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    async fn get_block_header_info(
        &self,
        hash: &bitcoin::BlockHash,
    ) -> Result<json::GetBlockHeaderResult> {
        self.call("getblockheader", &[into_json(hash)?, true.into()])
            .await
    }

    async fn get_mining_info(&self) -> Result<json::GetMiningInfoResult> {
        self.call("getmininginfo", &[]).await
    }

    /// Returns a data structure containing various state info regarding
    /// blockchain processing.
    async fn get_blockchain_info(&self) -> Result<json::GetBlockchainInfoResult> {
        let mut raw: serde_json::Value = self.call("getblockchaininfo", &[]).await?;
        // The softfork fields are not backwards compatible:
        // - 0.18.x returns a "softforks" array and a "bip9_softforks" map.
        // - 0.19.x returns a "softforks" map.
        Ok(if self.version().await? < 190000 {
            use Error::UnexpectedStructure as err;

            // First, remove both incompatible softfork fields.
            let map = raw.as_object_mut().ok_or(err)?;
            let bip9_softforks = map.remove("bip9_softforks").ok_or(err)?;
            let old_softforks = map.remove("softforks").ok_or(err)?;
            // Put back an empty "softforks" field.
            map.insert("softforks".into(), serde_json::Map::new().into());
            let mut ret: json::GetBlockchainInfoResult = serde_json::from_value(raw)?;

            // Then convert both softfork types and add them.
            for sf in old_softforks.as_array().ok_or(err)?.iter() {
                let json = sf.as_object().ok_or(err)?;
                let id = json.get("id").ok_or(err)?.as_str().ok_or(err)?;
                let reject = json.get("reject").ok_or(err)?.as_object().ok_or(err)?;
                let active = reject.get("status").ok_or(err)?.as_bool().ok_or(err)?;
                ret.softforks.insert(
                    id.into(),
                    json::Softfork {
                        type_: json::SoftforkType::Buried,
                        bip9: None,
                        height: None,
                        active: active,
                    },
                );
            }
            for (id, sf) in bip9_softforks.as_object().ok_or(err)?.iter() {
                #[derive(Deserialize)]
                struct OldBip9SoftFork {
                    pub status: json::Bip9SoftforkStatus,
                    pub bit: Option<u8>,
                    #[serde(rename = "startTime")]
                    pub start_time: i64,
                    pub timeout: u64,
                    pub since: u32,
                    pub statistics: Option<json::Bip9SoftforkStatistics>,
                }
                let sf: OldBip9SoftFork = serde_json::from_value(sf.clone())?;
                ret.softforks.insert(
                    id.into(),
                    json::Softfork {
                        type_: json::SoftforkType::Bip9,
                        bip9: Some(json::Bip9SoftforkInfo {
                            status: sf.status,
                            bit: sf.bit,
                            start_time: sf.start_time,
                            timeout: sf.timeout,
                            since: sf.since,
                            statistics: sf.statistics,
                        }),
                        height: None,
                        active: sf.status == json::Bip9SoftforkStatus::Active,
                    },
                );
            }
            ret
        } else {
            serde_json::from_value(raw)?
        })
    }

    /// Returns the numbers of block in the longest chain.
    async fn get_block_count(&self) -> Result<u64> {
        self.call("getblockcount", &[]).await
    }

    /// Returns the hash of the best (tip) block in the longest blockchain.
    async fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash> {
        self.call("getbestblockhash", &[]).await
    }

    /// Get block hash at a given height
    async fn get_block_hash(&self, height: u64) -> Result<bitcoin::BlockHash> {
        self.call("getblockhash", &[height.into()]).await
    }

    async fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<Transaction> {
        let mut args = [
            into_json(txid)?,
            into_json(false)?,
            opt_into_json(block_hash)?,
        ];
        let hex: String = self
            .call("getrawtransaction", handle_defaults(&mut args, &[null()]))
            .await?;
        let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    async fn get_raw_transaction_hex(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<String> {
        let mut args = [
            into_json(txid)?,
            into_json(false)?,
            opt_into_json(block_hash)?,
        ];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))
            .await
    }

    async fn get_raw_transaction_info(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<json::GetRawTransactionResult> {
        let mut args = [
            into_json(txid)?,
            into_json(true)?,
            opt_into_json(block_hash)?,
        ];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))
            .await
    }

    async fn get_block_filter(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<json::GetBlockFilterResult> {
        self.call("getblockfilter", &[into_json(block_hash)?]).await
    }

    async fn get_balance(
        &self,
        minconf: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Amount> {
        let mut args = [
            "*".into(),
            opt_into_json(minconf)?,
            opt_into_json(include_watchonly)?,
        ];
        Ok(Amount::from_btc(
            self.call(
                "getbalance",
                handle_defaults(&mut args, &[0.into(), null()]),
            )
            .await?,
        )?)
    }

    async fn get_balances(&self) -> Result<json::GetBalancesResult> {
        Ok(self.call("getbalances", &[]).await?)
    }

    async fn get_received_by_address(
        &self,
        address: &Address,
        minconf: Option<u32>,
    ) -> Result<Amount> {
        let mut args = [address.to_string().into(), opt_into_json(minconf)?];
        Ok(Amount::from_btc(
            self.call(
                "getreceivedbyaddress",
                handle_defaults(&mut args, &[null()]),
            )
            .await?,
        )?)
    }

    async fn get_transaction(
        &self,
        txid: &bitcoin::Txid,
        include_watchonly: Option<bool>,
    ) -> Result<json::GetTransactionResult> {
        let mut args = [into_json(txid)?, opt_into_json(include_watchonly)?];
        self.call("gettransaction", handle_defaults(&mut args, &[null()]))
            .await
    }

    async fn list_transactions(
        &self,
        label: Option<&str>,
        count: Option<usize>,
        skip: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<json::ListTransactionResult>> {
        let mut args = [
            label.unwrap_or("*").into(),
            opt_into_json(count)?,
            opt_into_json(skip)?,
            opt_into_json(include_watchonly)?,
        ];
        self.call(
            "listtransactions",
            handle_defaults(&mut args, &[10.into(), 0.into(), null()]),
        )
        .await
    }

    async fn list_since_block(
        &self,
        blockhash: Option<&bitcoin::BlockHash>,
        target_confirmations: Option<usize>,
        include_watchonly: Option<bool>,
        include_removed: Option<bool>,
    ) -> Result<json::ListSinceBlockResult> {
        let mut args = [
            opt_into_json(blockhash)?,
            opt_into_json(target_confirmations)?,
            opt_into_json(include_watchonly)?,
            opt_into_json(include_removed)?,
        ];
        self.call("listsinceblock", handle_defaults(&mut args, &[null()]))
            .await
    }

    async fn get_tx_out(
        &self,
        txid: &bitcoin::Txid,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<json::GetTxOutResult>> {
        let mut args = [
            into_json(txid)?,
            into_json(vout)?,
            opt_into_json(include_mempool)?,
        ];
        opt_result(
            self.call("gettxout", handle_defaults(&mut args, &[null()]))
                .await?,
        )
    }

    async fn get_tx_out_proof(
        &self,
        txids: &[bitcoin::Txid],
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<Vec<u8>> {
        let mut args = [into_json(txids)?, opt_into_json(block_hash)?];
        let hex: String = self
            .call("gettxoutproof", handle_defaults(&mut args, &[null()]))
            .await?;
        Ok(FromHex::from_hex(&hex)?)
    }

    async fn import_public_key(
        &self,
        pubkey: &PublicKey,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        let mut args = [
            pubkey.to_string().into(),
            opt_into_json(label)?,
            opt_into_json(rescan)?,
        ];
        self.call(
            "importpubkey",
            handle_defaults(&mut args, &[into_json("")?, null()]),
        )
        .await
    }

    async fn import_private_key(
        &self,
        privkey: &PrivateKey,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        let mut args = [
            privkey.to_string().into(),
            opt_into_json(label)?,
            opt_into_json(rescan)?,
        ];
        self.call(
            "importprivkey",
            handle_defaults(&mut args, &[into_json("")?, null()]),
        )
        .await
    }

    async fn import_address(
        &self,
        address: &Address,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        let mut args = [
            address.to_string().into(),
            opt_into_json(label)?,
            opt_into_json(rescan)?,
        ];
        self.call(
            "importaddress",
            handle_defaults(&mut args, &[into_json("")?, null()]),
        )
        .await
    }

    async fn import_address_script(
        &self,
        script: &Script,
        label: Option<&str>,
        rescan: Option<bool>,
        p2sh: Option<bool>,
    ) -> Result<()> {
        let mut args = [
            script.to_hex().into(),
            opt_into_json(label)?,
            opt_into_json(rescan)?,
            opt_into_json(p2sh)?,
        ];
        self.call(
            "importaddress",
            handle_defaults(&mut args, &[into_json("")?, true.into(), null()]),
        )
        .await
    }

    async fn import_multi<'a>(
        &self,
        requests: &'a [json::ImportMultiRequest<'a>],
        options: Option<&json::ImportMultiOptions>,
    ) -> Result<Vec<json::ImportMultiResult>> {
        let mut json_requests = Vec::with_capacity(requests.len());
        for req in requests {
            json_requests.push(serde_json::to_value(req)?);
        }
        let mut args = [json_requests.into(), opt_into_json(options)?];
        self.call("importmulti", handle_defaults(&mut args, &[null()]))
            .await
    }

    async fn set_label(&self, address: &Address, label: &str) -> Result<()> {
        self.call("setlabel", &[address.to_string().into(), label.into()])
            .await
    }

    async fn key_pool_refill(&self, new_size: Option<usize>) -> Result<()> {
        let mut args = [opt_into_json(new_size)?];
        self.call("keypoolrefill", handle_defaults(&mut args, &[null()]))
            .await
    }

    async fn list_unspent(
        &self,
        minconf: Option<usize>,
        maxconf: Option<usize>,
        addresses: Option<&[&Address]>,
        include_unsafe: Option<bool>,
        query_options: Option<json::ListUnspentQueryOptions>,
    ) -> Result<Vec<json::ListUnspentResultEntry>> {
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
            empty_arr(),
            into_json(true)?,
            null(),
        ];
        self.call("listunspent", handle_defaults(&mut args, &defaults))
            .await
    }

    /// To unlock, use [unlock_unspent].
    async fn lock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        let outputs: Vec<_> = outputs
            .into_iter()
            .map(|o| serde_json::to_value(JsonOutPoint::from(*o)).unwrap())
            .collect();
        self.call("lockunspent", &[false.into(), outputs.into()])
            .await
    }

    async fn unlock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        let outputs: Vec<_> = outputs
            .into_iter()
            .map(|o| serde_json::to_value(JsonOutPoint::from(*o)).unwrap())
            .collect();
        self.call("lockunspent", &[true.into(), outputs.into()])
            .await
    }

    async fn list_received_by_address(
        &self,
        address_filter: Option<&Address>,
        minconf: Option<u32>,
        include_empty: Option<bool>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<json::ListReceivedByAddressResult>> {
        let mut args = [
            opt_into_json(minconf)?,
            opt_into_json(include_empty)?,
            opt_into_json(include_watchonly)?,
            opt_into_json(address_filter)?,
        ];
        let defaults = [1.into(), false.into(), false.into(), null()];
        self.call(
            "listreceivedbyaddress",
            handle_defaults(&mut args, &defaults),
        )
        .await
    }

    async fn create_raw_transaction_hex(
        &self,
        utxos: &[json::CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<String> {
        let outs_converted = serde_json::Map::from_iter(
            outs.iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::from(v.as_btc()))),
        );
        let mut args = [
            into_json(utxos)?,
            into_json(outs_converted)?,
            opt_into_json(locktime)?,
            opt_into_json(replaceable)?,
        ];
        let defaults = [into_json(0i64)?, null()];
        self.call(
            "createrawtransaction",
            handle_defaults(&mut args, &defaults),
        )
        .await
    }

    async fn create_raw_transaction(
        &self,
        utxos: &[json::CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<Transaction> {
        let hex: String = self
            .create_raw_transaction_hex(utxos, outs, locktime, replaceable)
            .await?;
        let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    async fn fund_raw_transaction<R: RawTx + Send>(
        &self,
        tx: R,
        options: Option<&json::FundRawTransactionOptions>,
        is_witness: Option<bool>,
    ) -> Result<json::FundRawTransactionResult> {
        let mut args = [
            tx.raw_hex().into(),
            opt_into_json(options)?,
            opt_into_json(is_witness)?,
        ];
        let defaults = [empty_obj(), null()];
        self.call("fundrawtransaction", handle_defaults(&mut args, &defaults))
            .await
    }

    #[deprecated]
    async fn sign_raw_transaction<R: RawTx + Send>(
        &self,
        tx: R,
        utxos: Option<&[json::SignRawTransactionInput]>,
        private_keys: Option<&[PrivateKey]>,
        sighash_type: Option<json::SigHashType>,
    ) -> Result<json::SignRawTransactionResult> {
        let mut args = [
            tx.raw_hex().into(),
            opt_into_json(utxos)?,
            opt_into_json(private_keys)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [empty_arr(), empty_arr(), null()];
        self.call("signrawtransaction", handle_defaults(&mut args, &defaults))
            .await
    }

    async fn sign_raw_transaction_with_wallet<R: RawTx + Send>(
        &self,
        tx: R,
        utxos: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<json::SigHashType>,
    ) -> Result<json::SignRawTransactionResult> {
        let mut args = [
            tx.raw_hex().into(),
            opt_into_json(utxos)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [empty_arr(), null()];
        self.call(
            "signrawtransactionwithwallet",
            handle_defaults(&mut args, &defaults),
        )
        .await
    }

    async fn sign_raw_transaction_with_key<R: RawTx + Send>(
        &self,
        tx: R,
        privkeys: &[PrivateKey],
        prevtxs: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<json::SigHashType>,
    ) -> Result<json::SignRawTransactionResult> {
        let mut args = [
            tx.raw_hex().into(),
            into_json(privkeys)?,
            opt_into_json(prevtxs)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [empty_arr(), null()];
        self.call(
            "signrawtransactionwithkey",
            handle_defaults(&mut args, &defaults),
        )
        .await
    }

    async fn test_mempool_accept<R: RawTx + Sync>(
        &self,
        rawtxs: &[R],
    ) -> Result<Vec<json::TestMempoolAcceptResult>> {
        let hexes: Vec<serde_json::Value> = rawtxs
            .to_vec()
            .into_iter()
            .map(|r| r.raw_hex().into())
            .collect();
        self.call("testmempoolaccept", &[hexes.into()]).await
    }

    async fn stop(&self) -> Result<String> {
        self.call("stop", &[]).await
    }

    async fn verify_message(
        &self,
        address: &Address,
        signature: &Signature,
        message: &str,
    ) -> Result<bool> {
        let args = [
            address.to_string().into(),
            signature.to_string().into(),
            into_json(message)?,
        ];
        self.call("verifymessage", &args).await
    }

    /// Generate new address under own control
    async fn get_new_address(
        &self,
        label: Option<&str>,
        address_type: Option<json::AddressType>,
    ) -> Result<Address> {
        self.call(
            "getnewaddress",
            &[opt_into_json(label)?, opt_into_json(address_type)?],
        )
        .await
    }

    async fn get_address_info(&self, address: &Address) -> Result<json::GetAddressInfoResult> {
        self.call("getaddressinfo", &[address.to_string().into()])
            .await
    }

    /// Mine `block_num` blocks and pay coinbase to `address`
    ///
    /// Returns hashes of the generated blocks
    async fn generate_to_address(
        &self,
        block_num: u64,
        address: &Address,
    ) -> Result<Vec<bitcoin::BlockHash>> {
        self.call(
            "generatetoaddress",
            &[block_num.into(), address.to_string().into()],
        )
        .await
    }

    /// Mine up to block_num blocks immediately (before the RPC call returns)
    /// to an address in the wallet.
    async fn generate(
        &self,
        block_num: u64,
        maxtries: Option<u64>,
    ) -> Result<Vec<bitcoin::BlockHash>> {
        self.call("generate", &[block_num.into(), opt_into_json(maxtries)?])
            .await
    }

    /// Mark a block as invalid by `block_hash`
    async fn invalidate_block(&self, block_hash: &bitcoin::BlockHash) -> Result<()> {
        self.call("invalidateblock", &[into_json(block_hash)?])
            .await
    }

    /// Mark a block as valid by `block_hash`
    async fn reconsider_block(&self, block_hash: &bitcoin::BlockHash) -> Result<()> {
        self.call("reconsiderblock", &[into_json(block_hash)?])
            .await
    }

    /// Get txids of all transactions in a memory pool
    async fn get_raw_mempool(&self) -> Result<Vec<bitcoin::Txid>> {
        self.call("getrawmempool", &[]).await
    }

    /// Get mempool data for given transaction
    async fn get_mempool_entry(&self, txid: &bitcoin::Txid) -> Result<json::GetMempoolEntryResult> {
        self.call("getmempoolentry", &[into_json(txid)?]).await
    }

    async fn send_to_address(
        &self,
        address: &Address,
        amount: Amount,
        comment: Option<&str>,
        comment_to: Option<&str>,
        subtract_fee: Option<bool>,
        replaceable: Option<bool>,
        confirmation_target: Option<u32>,
        estimate_mode: Option<json::EstimateMode>,
    ) -> Result<bitcoin::Txid> {
        let mut args = [
            address.to_string().into(),
            into_json(amount.as_btc())?,
            opt_into_json(comment)?,
            opt_into_json(comment_to)?,
            opt_into_json(subtract_fee)?,
            opt_into_json(replaceable)?,
            opt_into_json(confirmation_target)?,
            opt_into_json(estimate_mode)?,
        ];
        self.call(
            "sendtoaddress",
            handle_defaults(
                &mut args,
                &[
                    "".into(),
                    "".into(),
                    false.into(),
                    false.into(),
                    6.into(),
                    null(),
                ],
            ),
        )
        .await
    }

    /// Returns data about each connected network node as an array of
    /// [`PeerInfo`][]
    ///
    /// [`PeerInfo`]: net/struct.PeerInfo.html
    async fn get_peer_info(&self) -> Result<Vec<json::GetPeerInfoResult>> {
        self.call("getpeerinfo", &[]).await
    }

    /// Requests that a ping be sent to all other nodes, to measure ping
    /// time.
    ///
    /// Results provided in `getpeerinfo`, `pingtime` and `pingwait` fields
    /// are decimal seconds.
    ///
    /// Ping command is handled in queue with all other commands, so it
    /// measures processing backlog, not just network ping.
    async fn ping(&self) -> Result<()> {
        self.call("ping", &[]).await
    }

    async fn send_raw_transaction<R: RawTx + Send>(&self, tx: R) -> Result<bitcoin::Txid> {
        self.call("sendrawtransaction", &[tx.raw_hex().into()])
            .await
    }

    async fn estimate_smart_fee(
        &self,
        conf_target: u16,
        estimate_mode: Option<json::EstimateMode>,
    ) -> Result<json::EstimateSmartFeeResult> {
        let mut args = [into_json(conf_target)?, opt_into_json(estimate_mode)?];
        self.call("estimatesmartfee", handle_defaults(&mut args, &[null()]))
            .await
    }

    /// Waits for a specific new block and returns useful info about it.
    /// Returns the current block on timeout or exit.
    ///
    /// # Arguments
    ///
    /// 1. `timeout`: Time in milliseconds to wait for a response. 0
    /// indicates no timeout.
    async fn wait_for_new_block(&self, timeout: u64) -> Result<json::BlockRef> {
        self.call("waitfornewblock", &[into_json(timeout)?]).await
    }

    /// Waits for a specific new block and returns useful info about it.
    /// Returns the current block on timeout or exit.
    ///
    /// # Arguments
    ///
    /// 1. `blockhash`: Block hash to wait for.
    /// 2. `timeout`: Time in milliseconds to wait for a response. 0
    /// indicates no timeout.
    async fn wait_for_block(
        &self,
        blockhash: &bitcoin::BlockHash,
        timeout: u64,
    ) -> Result<json::BlockRef> {
        let args = [into_json(blockhash)?, into_json(timeout)?];
        self.call("waitforblock", &args).await
    }

    async fn wallet_create_funded_psbt(
        &self,
        inputs: &[json::CreateRawTransactionInput],
        outputs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        options: Option<json::WalletCreateFundedPsbtOptions>,
        bip32derivs: Option<bool>,
    ) -> Result<json::WalletCreateFundedPsbtResult> {
        let outputs_converted = serde_json::Map::from_iter(
            outputs
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::from(v.as_btc()))),
        );
        let mut args = [
            into_json(inputs)?,
            into_json(outputs_converted)?,
            opt_into_json(locktime)?,
            opt_into_json(options)?,
            opt_into_json(bip32derivs)?,
        ];
        self.call(
            "walletcreatefundedpsbt",
            handle_defaults(
                &mut args,
                &[0.into(), serde_json::Map::new().into(), false.into()],
            ),
        )
        .await
    }

    async fn get_descriptor_info(&self, desc: &str) -> Result<json::GetDescriptorInfoResult> {
        self.call("getdescriptorinfo", &[desc.to_string().into()])
            .await
    }

    async fn combine_psbt(&self, psbts: &[String]) -> Result<String> {
        self.call("combinepsbt", &[into_json(psbts)?]).await
    }

    async fn finalize_psbt(
        &self,
        psbt: &str,
        extract: Option<bool>,
    ) -> Result<json::FinalizePsbtResult> {
        let mut args = [into_json(psbt)?, opt_into_json(extract)?];
        self.call("finalizepsbt", handle_defaults(&mut args, &[true.into()]))
            .await
    }

    async fn derive_addresses(
        &self,
        descriptor: &str,
        range: Option<[u32; 2]>,
    ) -> Result<Vec<Address>> {
        let mut args = [into_json(descriptor)?, opt_into_json(range)?];
        self.call("deriveaddresses", handle_defaults(&mut args, &[null()]))
            .await
    }

    async fn rescan_blockchain(
        &self,
        start_from: Option<usize>,
        stop_height: Option<usize>,
    ) -> Result<(usize, Option<usize>)> {
        let mut args = [opt_into_json(start_from)?, opt_into_json(stop_height)?];

        #[derive(Deserialize)]
        struct Response {
            pub start_height: usize,
            pub stop_height: Option<usize>,
        }
        let res: Response = self
            .call(
                "rescanblockchain",
                handle_defaults(&mut args, &[0.into(), null()]),
            )
            .await?;
        Ok((res.start_height, res.stop_height))
    }

    /// Returns statistics about the unspent transaction output set.
    /// This call may take some time.
    async fn get_tx_out_set_info(&self) -> Result<json::GetTxOutSetInfoResult> {
        self.call("gettxoutsetinfo", &[]).await
    }

    /// Returns information about network traffic, including bytes in, bytes out,
    /// and current time.
    async fn get_net_totals(&self) -> Result<json::GetNetTotalsResult> {
        self.call("getnettotals", &[]).await
    }

    /// Returns the estimated network hashes per second based on the last n blocks.
    async fn get_network_hash_ps(&self, nblocks: Option<u64>, height: Option<u64>) -> Result<f64> {
        let mut args = [opt_into_json(nblocks)?, opt_into_json(height)?];
        self.call(
            "getnetworkhashps",
            handle_defaults(&mut args, &[null(), null()]),
        )
        .await
    }

    /// Returns the total uptime of the server in seconds
    async fn uptime(&self) -> Result<u64> {
        self.call("uptime", &[]).await
    }
}

/// Client implements a JSON-RPC client for the Bitcoin Core daemon or compatible APIs.
pub struct Client {
    url: String,
    client: reqwest::Client,
    nonce: Arc<Mutex<u64>>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "bitcoincore_rpc::Client(jsonrpc::Client(url={}))",
            self.url
        )
    }
}

impl Client {
    /// Creates a client to a bitcoind JSON-RPC server.
    ///
    /// Can only return [Err] when using cookie authentication.
    pub fn new(url: String, auth: Auth) -> Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );

        let (user, pass) = auth.get_user_pass()?;

        // Set Authorization header
        if let Some(ref user) = user {
            let mut auth = user.clone();
            auth.push(':');
            if let Some(ref pass) = pass {
                auth.push_str(&pass[..]);
            }
            let value = format!("Basic {}", &base64::encode(auth.as_bytes()));
            headers.insert(
                "Authorization",
                reqwest::header::HeaderValue::from_str(&value).unwrap(),
            );
        }

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;

        Ok(Client {
            url,
            client,
            nonce: Arc::new(Mutex::new(0)),
        })
    }

    /// Create a new Client.
    pub fn from_client(url: String, client: reqwest::Client) -> Client {
        Client {
            url,
            client,
            nonce: Arc::new(Mutex::new(0)),
        }
    }

    /// Get the underlying JSONRPC client.
    pub fn get_client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Get the last nonce.
    pub async fn last_nonce(&self) -> u64 {
        *self.nonce.lock().await
    }
}

#[async_trait]
impl RpcApi for Client {
    /// Call an `cmd` rpc with given `args` list
    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        let mut nonce = self.nonce.lock().await;
        *nonce += 1;

        let req = JsonRpcRequest {
            method: cmd,
            params: args,
            id: From::from(*nonce),
            jsonrpc: Some("2.0"),
        };

        if log_enabled!(Debug) {
            debug!(target: "bitcoincore_rpc", "JSON-RPC request: {} {}", cmd, serde_json::Value::from(args));
        }

        let resp = self
            .client
            .post(&self.url)
            .json(&req)
            .send()
            .await?
            .json::<JsonRpcResponse>()
            .await?;

        if resp.jsonrpc != None && resp.jsonrpc != Some(From::from("2.0")) {
            return Err(Error::VersionMismatch);
        }
        if resp.id != req.id {
            return Err(Error::NonceMismatch);
        }

        log_response(cmd, &resp);
        Ok(resp.into_result()?)
    }
}

fn log_response(cmd: &str, resp: &JsonRpcResponse) {
    if log_enabled!(Warn) || log_enabled!(Debug) || log_enabled!(Trace) {
        if let Some(ref e) = resp.error {
            if log_enabled!(Debug) {
                debug!(target: "bitcoincore_rpc", "JSON-RPC error for {}: {:?}", cmd, e);
            }
        } else if log_enabled!(Trace) {
            let result = resp.result.as_ref().unwrap_or(&serde_json::Value::Null);
            trace!(target: "bitcoincore_rpc", "JSON-RPC response for {}: {}", cmd, result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin;
    use serde_json;

    #[tokio::test]
    async fn test_raw_tx() {
        use bitcoin::consensus::encode;
        let client = Client::new("http://localhost/".into(), Auth::None).unwrap();
        let tx: bitcoin::Transaction = encode::deserialize(&Vec::<u8>::from_hex("0200000001586bd02815cf5faabfec986a4e50d25dbee089bd2758621e61c5fab06c334af0000000006b483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2dfeffffff021dc4260c010000001976a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac00e1f505000000001976a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88acfd211500").unwrap()).unwrap();

        assert!(client.send_raw_transaction(&tx).await.is_err());
        assert!(client
            .send_raw_transaction(&encode::serialize(&tx))
            .await
            .is_err());
        assert!(client.send_raw_transaction("deadbeef").await.is_err());
        assert!(client
            .send_raw_transaction("deadbeef".to_owned())
            .await
            .is_err());
    }

    fn test_handle_defaults_inner() -> Result<()> {
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

    #[test]
    fn test_handle_defaults() {
        test_handle_defaults_inner().unwrap();
    }
}
