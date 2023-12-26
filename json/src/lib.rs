//! # Rust Client for Bitcoin SV API
//!
//! This is a client library for the Bitcoin SV JSON-RPC API.
//!

#![crate_name = "bitcoinsv_rpc_json"]
#![crate_type = "rlib"]

pub extern crate bitcoin;
#[allow(unused)]
#[macro_use] // `macro_use` is needed for v1.24.0 compilation.
extern crate serde;
extern crate serde_json;

use std::collections::HashMap;


use bitcoin::address::NetworkUnchecked;
use bitcoin::block::Version;
use bitcoin::consensus::encode;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::sha256;
use bitcoin::{Address, Amount, PublicKey, SignedAmount, Transaction, ScriptBuf, Script, bip158, bip32, Network};
use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};
use std::fmt;

//TODO(stevenroose) consider using a Time type

/// A module used for serde serialization of bytes in hexadecimal format.
///
/// The module is compatible with the serde attribute.
pub mod serde_hex {
    use hex::FromHex;
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&*hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let hex_str: String = ::serde::Deserialize::deserialize(d)?;
        Ok(FromHex::from_hex(&hex_str).map_err(D::Error::custom)?)
    }

    pub mod opt {
        use hex::FromHex;
        use serde::de::Error;
        use serde::{Deserializer, Serializer};

        pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match *b {
                None => s.serialize_none(),
                Some(ref b) => s.serialize_str(&*hex::encode(b)),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            let hex_str: String = ::serde::Deserialize::deserialize(d)?;
            Ok(Some(FromHex::from_hex(&hex_str).map_err(D::Error::custom)?))
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetworkInfoResultNetwork {
    pub name: String,
    pub limited: bool,
    pub reachable: bool,
    pub proxy: String,
    pub proxy_randomize_credentials: bool,
}

#[cfg(test)]
mod ninfo_network_tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_deserialize_get_network_info_result_network() {
        let json_data = r#"
            {
              "name": "ipv4",
              "limited": false,
              "reachable": true,
              "proxy": "",
              "proxy_randomize_credentials": false
            }
        "#;

        let result: GetNetworkInfoResultNetwork = serde_json::from_str(json_data).unwrap();

        assert_eq!(result.name, "ipv4");
        assert_eq!(result.limited, false);
        assert_eq!(result.reachable, true);
        assert_eq!(result.proxy, "");
        assert_eq!(result.proxy_randomize_credentials, false);
    }
}


#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetworkInfoResultAddress {
    pub address: String,
    pub port: u64,
    pub score: u64,
}

#[cfg(test)]
mod ninfo_address_tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_deserialize_get_network_info_result_address() {
        let json_data = r#"
            {
              "address": "192.168.32.145",
              "port": 8333,
              "score": 13436
            }
        "#;

        let result: GetNetworkInfoResultAddress = serde_json::from_str(json_data).unwrap();

        assert_eq!(result.address, "192.168.32.145");
        assert_eq!(result.port, 8333);
        assert_eq!(result.score, 13436);
    }
}


#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetworkInfoResult {
    pub version: usize,
    pub subversion: String,
    #[serde(rename = "protocolversion")]
    pub protocol_version: usize,
    #[serde(rename = "localservices")]
    pub local_services: String,
    #[serde(rename = "localrelay")]
    pub local_relay: bool,
    #[serde(rename = "timeoffset")]
    pub time_offset: isize,
    #[serde(rename = "txnpropagationfreq")]
    pub txn_propagation_freq: i64,
    #[serde(rename = "txnpropagationqlen")]
    pub txn_propagation_qlen: u64,
    #[serde(rename = "networkactive")]
    pub network_active: bool,
    pub connections: usize,
    #[serde(rename = "addresscount")]
    pub address_count: u64,
    #[serde(rename = "streampolicies")]
    pub stream_policies: String,
    pub networks: Vec<GetNetworkInfoResultNetwork>,
    #[serde(rename = "relayfee", with = "bitcoin::amount::serde::as_btc")]
    pub relay_fee: Amount,
    #[serde(rename = "minconsolidationfactor")]
    pub min_consolidation_factor: u64,
    #[serde(rename = "maxconsolidationinputscriptsize")]
    pub max_consolidation_input_script_size: u64,
    #[serde(rename = "minconfconsolidationinput")]
    pub min_conf_consolidation_input: u64,
    #[serde(rename = "minconsolidationinputmaturity")]
    pub min_consolidation_input_maturity: u64,
    #[serde(rename = "acceptnonstdconsolidationinput")]
    pub accept_non_std_consolidation_input: bool,
    #[serde(rename = "localaddresses")]
    pub local_addresses: Vec<GetNetworkInfoResultAddress>,
    pub warnings: String,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockResultStatus {
    pub validity: String,
    pub data: bool,
    pub undo: bool,
    pub failed: bool,
    pub parent_failed: bool,
    pub disk_meta: bool,
    pub soft_reject: bool,
    pub double_spend: bool,
    pub soft_consensus_frozen: bool,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockResult {
    pub hash: bitcoin::BlockHash,
    pub confirmations: i32,
    pub size: usize,
    pub height: usize,
    pub version: i32,
    #[serde(default, rename = "versionHex", with = "crate::serde_hex::opt")]
    pub version_hex: Option<Vec<u8>>,
    pub merkleroot: bitcoin::hash_types::TxMerkleNode,
    pub tx: Vec<bitcoin::Txid>,
    pub time: usize,
    pub mediantime: Option<u64>,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    #[serde(with = "crate::serde_hex")]
    pub chainwork: Vec<u8>,
    pub num_tx: u64,
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: Option<bitcoin::BlockHash>,
    #[serde(rename = "nextblockhash")]
    pub next_block_hash: Option<bitcoin::BlockHash>,
    pub status: GetBlockResultStatus,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockHeaderResult {
    pub hash: bitcoin::BlockHash,
    pub confirmations: i32,
    pub size: u64,
    pub height: u64,
    pub version: Version,
    #[serde(default, rename = "versionHex", with = "crate::serde_hex::opt")]
    pub version_hex: Option<Vec<u8>>,
    #[serde(rename = "merkleroot")]
    pub merkle_root: bitcoin::hash_types::TxMerkleNode,
    pub num_tx: usize,
    pub time: u64,
    #[serde(rename = "mediantime")]
    pub median_time: Option<u64>,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    #[serde(with = "crate::serde_hex")]
    pub chainwork: Vec<u8>,
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: Option<bitcoin::BlockHash>,
    #[serde(rename = "nextblockhash")]
    pub next_block_hash: Option<bitcoin::BlockHash>,
    pub status: GetBlockResultStatus,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockStatsResult {
    #[serde(rename = "avgfee", with = "bitcoin::amount::serde::as_sat")]
    pub avg_fee: Amount,
    #[serde(rename = "avgfeerate", with = "bitcoin::amount::serde::as_sat")]
    pub avg_fee_rate: Amount,
    #[serde(rename = "avgtxsize")]
    pub avg_tx_size: u32,
    #[serde(rename = "blockhash")]
    pub block_hash: bitcoin::BlockHash,
    #[serde(rename = "feerate_percentiles")]
    pub height: u64,
    pub ins: u64,
    #[serde(rename = "maxfee", with = "bitcoin::amount::serde::as_sat")]
    pub max_fee: Amount,
    #[serde(rename = "maxfeerate", with = "bitcoin::amount::serde::as_sat")]
    pub max_fee_rate: Amount,
    #[serde(rename = "maxtxsize")]
    pub max_tx_size: u32,
    #[serde(rename = "medianfee", with = "bitcoin::amount::serde::as_sat")]
    pub median_fee: Amount,
    #[serde(rename = "mediantime")]
    pub median_time: u64,
    #[serde(rename = "mediantxsize")]
    pub median_tx_size: u32,
    #[serde(rename = "minfee", with = "bitcoin::amount::serde::as_sat")]
    pub min_fee: Amount,
    #[serde(rename = "minfeerate", with = "bitcoin::amount::serde::as_sat")]
    pub min_fee_rate: Amount,
    #[serde(rename = "mintxsize")]
    pub min_tx_size: u32,
    pub outs: usize,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub subsidy: Amount,
    pub time: u64,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub total_out: Amount,
    pub total_size: usize,
    #[serde(rename = "totalfee", with = "bitcoin::amount::serde::as_sat")]
    pub total_fee: Amount,
    pub txs: usize,
    pub utxo_increase: i32,
    pub utxo_size_inc: i32,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockStatsResultPartial {
    #[serde(
        default,
        rename = "avgfee",
        with = "bitcoin::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub avg_fee: Option<Amount>,
    #[serde(
        default,
        rename = "avgfeerate",
        with = "bitcoin::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub avg_fee_rate: Option<Amount>,
    #[serde(default, rename = "avgtxsize", skip_serializing_if = "Option::is_none")]
    pub avg_tx_size: Option<u32>,
    #[serde(default, rename = "blockhash", skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<bitcoin::BlockHash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ins: Option<usize>,
    #[serde(
        default,
        rename = "maxfee",
        with = "bitcoin::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_fee: Option<Amount>,
    #[serde(
        default,
        rename = "maxfeerate",
        with = "bitcoin::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_fee_rate: Option<Amount>,
    #[serde(default, rename = "maxtxsize", skip_serializing_if = "Option::is_none")]
    pub max_tx_size: Option<u32>,
    #[serde(
        default,
        rename = "medianfee",
        with = "bitcoin::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub median_fee: Option<Amount>,
    #[serde(default, rename = "mediantime", skip_serializing_if = "Option::is_none")]
    pub median_time: Option<u64>,
    #[serde(default, rename = "mediantxsize", skip_serializing_if = "Option::is_none")]
    pub median_tx_size: Option<u32>,
    #[serde(
        default,
        rename = "minfee",
        with = "bitcoin::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_fee: Option<Amount>,
    #[serde(
        default,
        rename = "minfeerate",
        with = "bitcoin::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_fee_rate: Option<Amount>,
    #[serde(default, rename = "mintxsize", skip_serializing_if = "Option::is_none")]
    pub min_tx_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outs: Option<usize>,
    #[serde(
        default,
        with = "bitcoin::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub subsidy: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<u64>,
    #[serde(
        default,
        with = "bitcoin::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub total_out: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_size: Option<usize>,
    #[serde(
        default,
        rename = "totalfee",
        with = "bitcoin::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub total_fee: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txs: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utxo_increase: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utxo_size_inc: Option<i32>,
}

#[derive(Clone)]
pub enum BlockStatsFields {
    AverageFee,
    AverageFeeRate,
    AverageTxSize,
    BlockHash,
    Height,
    Ins,
    MaxFee,
    MaxFeeRate,
    MaxTxSize,
    MedianFee,
    MedianTime,
    MedianTxSize,
    MinFee,
    MinFeeRate,
    MinTxSize,
    Outs,
    Subsidy,
    Time,
    TotalOut,
    TotalSize,
    TotalFee,
    Txs,
    UtxoIncrease,
    UtxoSizeIncrease,
}

impl BlockStatsFields {
    fn get_rpc_keyword(&self) -> &str {
        match *self {
            BlockStatsFields::AverageFee => "avgfee",
            BlockStatsFields::AverageFeeRate => "avgfeerate",
            BlockStatsFields::AverageTxSize => "avgtxsize",
            BlockStatsFields::BlockHash => "blockhash",
            BlockStatsFields::Height => "height",
            BlockStatsFields::Ins => "ins",
            BlockStatsFields::MaxFee => "maxfee",
            BlockStatsFields::MaxFeeRate => "maxfeerate",
            BlockStatsFields::MaxTxSize => "maxtxsize",
            BlockStatsFields::MedianFee => "medianfee",
            BlockStatsFields::MedianTime => "mediantime",
            BlockStatsFields::MedianTxSize => "mediantxsize",
            BlockStatsFields::MinFee => "minfee",
            BlockStatsFields::MinFeeRate => "minfeerate",
            BlockStatsFields::MinTxSize => "minfeerate",
            BlockStatsFields::Outs => "outs",
            BlockStatsFields::Subsidy => "subsidy",
            BlockStatsFields::Time => "time",
            BlockStatsFields::TotalOut => "total_out",
            BlockStatsFields::TotalSize => "total_size",
            BlockStatsFields::TotalFee => "totalfee",
            BlockStatsFields::Txs => "txs",
            BlockStatsFields::UtxoIncrease => "utxo_increase",
            BlockStatsFields::UtxoSizeIncrease => "utxo_size_inc",
        }
    }
}

impl fmt::Display for BlockStatsFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.get_rpc_keyword())
    }
}

impl From<BlockStatsFields> for serde_json::Value {
    fn from(bsf: BlockStatsFields) -> Self {
        Self::from(bsf.to_string())
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetMiningInfoResult {
    pub blocks: u32,
    #[serde(rename = "currentblocksize")]
    pub current_block_size: u64,
    #[serde(rename = "currentblocktx")]
    pub current_block_tx: u64,
    pub difficulty: f64,
    pub errors: String,
    #[serde(rename = "networkhashps")]
    pub network_hash_ps: f64,
    #[serde(rename = "pooledtx")]
    pub pooled_tx: u64,
    pub chain: Network,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVinScriptSig {
    pub asm: String,
    #[serde(with = "crate::serde_hex")]
    pub hex: Vec<u8>,
}

impl GetRawTransactionResultVinScriptSig {
    pub fn script(&self) -> Result<ScriptBuf, encode::Error> {
        Ok(ScriptBuf::from(self.hex.clone()))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVin {
    pub sequence: u32,
    /// The raw scriptSig in case of a coinbase tx.
    #[serde(default, with = "crate::serde_hex::opt")]
    pub coinbase: Option<Vec<u8>>,
    /// Not provided for coinbase txs.
    pub txid: Option<bitcoin::Txid>,
    /// Not provided for coinbase txs.
    pub vout: Option<u32>,
    /// The scriptSig in case of a non-coinbase tx.
    pub script_sig: Option<GetRawTransactionResultVinScriptSig>,
}

impl GetRawTransactionResultVin {
    /// Whether this input is from a coinbase tx.
    /// The [txid], [vout] and [script_sig] fields are not provided
    /// for coinbase transactions.
    pub fn is_coinbase(&self) -> bool {
        self.coinbase.is_some()
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVoutScriptPubKey {
    pub asm: String,
    #[serde(with = "crate::serde_hex")]
    pub hex: Vec<u8>,
    #[serde(rename = "type")]
    pub type_: Option<ScriptPubkeyType>,
}

impl GetRawTransactionResultVoutScriptPubKey {
    pub fn script(&self) -> Result<ScriptBuf, encode::Error> {
        Ok(ScriptBuf::from(self.hex.clone()))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVout {
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub value: Amount,
    pub n: u32,
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResult {
    #[serde(with = "crate::serde_hex")]
    pub hex: Vec<u8>,
    pub txid: bitcoin::Txid,
    pub hash: bitcoin::Wtxid,
    pub version: u32,
    pub size: usize,
    pub locktime: u32,
    pub vin: Vec<GetRawTransactionResultVin>,
    pub vout: Vec<GetRawTransactionResultVout>,
    #[serde(rename = "blockhash")]
    pub block_hash: Option<bitcoin::BlockHash>,
    pub confirmations: Option<u32>,
    pub time: Option<usize>,
    #[serde(rename = "blocktime")]
    pub block_time: Option<usize>,
    #[serde(rename = "blockheight")]
    pub block_height: Option<u32>,
}

impl GetRawTransactionResult {
    /// Whether this tx is a coinbase tx.
    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1 && self.vin[0].is_coinbase()
    }

    pub fn transaction(&self) -> Result<Transaction, encode::Error> {
        Ok(encode::deserialize(&self.hex)?)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTxOutResult {
    pub bestblock: bitcoin::BlockHash,
    pub confirmations: u32,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub value: Amount,
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
    pub coinbase: bool,
}


#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptPubkeyType {
    Nonstandard,
    Pubkey,
    PubkeyHash,
    ScriptHash,
    MultiSig,
    NullData,
}

/// Models the result of "getblockchaininfo"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetBlockchainInfoResult {
    /// Current network name as defined in BIP70 (main, test, signet, regtest)
    #[serde(deserialize_with = "deserialize_bip70_network")]
    pub chain: Network,
    /// The current number of blocks processed in the server
    pub blocks: u64,
    /// The current number of headers we have validated
    pub headers: u64,
    /// The hash of the currently best block
    #[serde(rename = "bestblockhash")]
    pub best_block_hash: bitcoin::BlockHash,
    /// The current difficulty
    pub difficulty: f64,
    /// Median time for the current best block
    #[serde(rename = "mediantime")]
    pub median_time: u64,
    /// Estimate of verification progress [0..1]
    #[serde(rename = "verificationprogress")]
    pub verification_progress: f64,
    /// Total amount of work in active chain, in hexadecimal
    #[serde(rename = "chainwork", with = "crate::serde_hex")]
    pub chain_work: Vec<u8>,
    /// If the blocks are subject to pruning
    pub pruned: bool,
    // todo: skipped the softforks field
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ImportMultiRequestScriptPubkey<'a> {
    Address(&'a Address),
    Script(&'a Script),
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolInfoResult {
    /// Current tx count
    pub size: u64,
    #[serde(rename = "journalsize")]
    pub journal_size: u64,
    #[serde(rename = "nonfinalsize")]
    pub non_final_size: u64,
    pub bytes: u64,
    /// Total memory usage for the mempool
    pub usage: usize,
    #[serde(rename = "usagedisk")]
    pub usage_disk: u64,
    #[serde(rename = "usagecpfp")]
    pub usage_cpfp: u64,
    #[serde(rename = "nonfinalusage")]
    pub non_final_usage: u64,
    /// Maximum memory usage for the mempool
    #[serde(rename = "maxmempool")]
    pub max_mempool: usize,
    #[serde(rename = "maxmempoolsizedisk")]
    pub max_mempool_size_disk: u64,
    #[serde(rename = "maxmempoolsizecpfp")]
    pub max_mempool_size_cpfp: u64,
    #[serde(rename = "mempoolminfee")]
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub mempool_min_fee: Amount,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolEntryResult {
    pub size: u64,
    /// Transaction fee in BSV
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub fee: Amount,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    #[serde(rename = "modifiedfee")]
    pub modified_fee: Amount,
    /// Local time transaction entered pool in seconds since 1 Jan 1970 GMT
    pub time: u64,
    /// Block height when transaction entered pool
    pub height: u64,
    /// Unconfirmed transactions used as inputs for this transaction
    pub depends: Vec<bitcoin::Txid>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetPeerInfoResultStream {
    #[serde(rename = "streamtype")]
    pub stream_type: String,
    /// The time of the last send
    #[serde(rename = "lastsend")]
    pub last_send: u64,
    /// The time of the last receive
    #[serde(rename = "lastrecv")]
    pub last_recv: u64,
    /// The total bytes sent
    #[serde(rename = "bytessent")]
    pub bytes_sent: u64,
    /// The total bytes received
    #[serde(rename = "bytesrecv")]
    pub bytes_recv: u64,
    #[serde(rename = "sendsize")]
    pub send_size: u64,
    #[serde(rename = "recvsize")]
    pub recv_size: u64,
    #[serde(rename = "sendmemory")]
    pub send_memory: u64,
    #[serde(rename = "spotrecvbw")]
    pub spot_recv_bw: u64,
    #[serde(rename = "minuterecvbw")]
    pub minute_recv_bw: u64,
    #[serde(rename = "pauserecv")]
    pub pause_recv: bool,
}

/// Models the result of "getpeerinfo"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetPeerInfoResult {
    /// Peer index
    pub id: u64,
    /// The IP address and port of the peer
    pub addr: String,
    /// Local address as reported by the peer
    #[serde(rename = "addrlocal")]
    pub addr_local: Option<String>,
    /// The services offered
    pub services: String,
    /// Whether peer has asked us to relay transactions to it
    #[serde(rename = "relaytxes")]
    pub relay_txes: bool,
    /// The time of the last send
    #[serde(rename = "lastsend")]
    pub last_send: u64,
    /// The time of the last receive
    #[serde(rename = "lastrecv")]
    pub last_recv: u64,
    #[serde(rename = "sendsize")]
    pub send_size: u64,
    #[serde(rename = "recvsize")]
    pub recv_size: u64,
    #[serde(rename = "sendmemory")]
    pub send_memory: u64,
    #[serde(rename = "pausesend")]
    pub pause_send: bool,
    #[serde(rename = "unpausesend")]
    pub unpause_send: bool,
    /// The total bytes sent
    #[serde(rename = "bytessent")]
    pub bytes_sent: u64,
    /// The total bytes received
    #[serde(rename = "bytesrecv")]
    pub bytes_recv: u64,
    #[serde(rename = "avgrecvbw")]
    pub avg_recv_bw: u64,
    #[serde(rename = "associd")]
    pub assoc_id: String,
    #[serde(rename = "streampolicy")]
    pub stream_policy: String,
    pub streams: Vec<GetPeerInfoResultStream>,
    #[serde(rename = "authconn")]
    pub auth_conn: bool,
    /// The connection time
    #[serde(rename = "conntime")]
    pub conn_time: u64,
    /// The time offset in seconds
    #[serde(rename = "timeoffset")]
    pub time_offset: i64,
    /// ping time (if available)
    #[serde(rename = "pingtime")]
    pub ping_time: Option<f64>,
    /// minimum observed ping time (if any at all)
    #[serde(rename = "minping")]
    pub min_ping: Option<f64>,
    /// ping wait (if non-zero)
    #[serde(rename = "pingwait")]
    pub ping_wait: Option<f64>,
    /// The peer version, such as 70001
    pub version: u64,
    /// The string version
    pub subver: String,
    /// Inbound (true) or Outbound (false)
    pub inbound: bool,
    /// Whether connection was due to `addnode`/`-connect` or if it was an
    /// automatic/inbound connection
    #[serde(rename = "addnode")]
    pub add_node: Option<bool>,
    /// The starting height (block) of the peer
    #[serde(rename = "startingheight")]
    pub starting_height: i64,
    /// The ban score
    #[serde(rename = "banscore")]
    pub ban_score: Option<i64>,
    /// The last header we have in common with this peer
    pub synced_headers: i64,
    /// The last block we have in common with this peer
    pub synced_blocks: i64,
    /// The heights of blocks we're currently asking from this peer
    #[serde(rename = "inflight")]
    pub in_flight: Vec<u64>,
    /// Whether the peer is whitelisted
    #[serde(rename = "whitelisted")]
    pub white_listed: Option<bool>,
    /// The total bytes sent aggregated by message type
    #[serde(rename = "bytessent_per_msg")]
    pub bytes_sent_per_msg: HashMap<String, u64>,
    /// The total bytes received aggregated by message type
    #[serde(rename = "bytesrecv_per_msg")]
    pub bytes_recv_per_msg: HashMap<String, u64>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetAddedNodeInfoResult {
    /// The node IP address or name (as provided to addnode)
    #[serde(rename = "addednode")]
    pub added_node: String,
    ///  If connected
    pub connected: bool,
    /// Only when connected = true
    pub addresses: Vec<GetAddedNodeInfoResultAddress>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetAddedNodeInfoResultAddress {
    /// The bitcoin server IP and port we're connected to
    pub address: String,
    /// connection, inbound or outbound
    pub connected: GetAddedNodeInfoResultAddressType,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetAddedNodeInfoResultAddressType {
    Inbound,
    Outbound,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ListBannedResult {
    pub address: String,
    pub banned_until: u64,
    pub ban_created: u64,
    pub ban_reason: String,
}

/// Models the request options of "getblocktemplate"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateOptions {
    pub mode: GetBlockTemplateModes,
    /// List of client side supported features
    pub capabilities: Vec<GetBlockTemplateCapabilities>,
}

/// Enum to represent client-side supported features
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateCapabilities {
    // No features supported yet. In the future this could be, for example, Proposal and Longpolling
}

/// Enum to represent client-side supported features.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateModes {
    /// Using this mode, the server build a block template and return it as
    /// response to the request. This is the default mode.
    Template,
    // TODO: Support for "proposal" mode is not yet implemented on the client
    // side.
}

/// Models the result of "getblocktemplate"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateResult {
    /// List of features the getblocktemplate implementation supports
    pub capabilities: Vec<String>,
    /// Block header version
    pub version: u32,
    /// The previous block hash the current template is mining on
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: bitcoin::BlockHash,
    /// List of transactions included in the template block
    pub transactions: Vec<GetBlockTemplateResultTransaction>,
    /// Data that should be included in the coinbase's scriptSig content. Only
    /// the values (hexadecimal byte-for-byte) in this map should be included,
    /// not the keys. This does not include the block height, which is required
    /// to be included in the scriptSig by BIP 0034. It is advisable to encode
    /// values inside "PUSH" opcodes, so as to not inadvertently expend SIGOPs
    /// (which are counted toward limits, despite not being executed).
    pub coinbaseaux: HashMap<String, String>,
    /// Total funds available for the coinbase
    #[serde(rename = "coinbasevalue", with = "bitcoin::amount::serde::as_sat", default)]
    pub coinbase_value: Amount,
    /// Id used in longpoll requests for this template.
    pub longpollid: String,
    /// The number which valid hashes must be less than, in big-endian
    #[serde(with = "crate::serde_hex")]
    pub target: Vec<u8>,
    /// The minimum timestamp appropriate for the next block time. Expressed as
    /// UNIX timestamp.
    #[serde(rename = "mintime")]
    pub min_time: u64,
    /// List of things that may be changed by the client before submitting a
    /// block
    pub mutable: Vec<GetBlockTemplateResulMutations>,
    /// A range of valid nonces
    #[serde(with = "crate::serde_hex", rename = "noncerange")]
    pub nonce_range: Vec<u8>,
    /// Block size limit
    #[serde(rename = "sizelimit")]
    pub size_limit: u64,
    /// current time on the server
    #[serde(rename = "curtime")]
    pub cur_time: u64,
    /// The compressed difficulty in hexadecimal
    #[serde(with = "crate::serde_hex")]
    pub bits: Vec<u8>,
    /// The height of the block we will be mining: `current height + 1`
    pub height: u64,
}

/// Models a single transaction entry in the result of "getblocktemplate"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateResultTransaction {
    /// The serilaized transaction bytes
    #[serde(with = "crate::serde_hex", rename = "data")]
    pub raw_tx: Vec<u8>,
    /// The transaction id
    #[serde(rename = "txid")]
    pub tx_id: bitcoin::Txid,
    pub hash: bitcoin::Txid,
    /// Transactions that must be in present in the final block if this one is.
    /// Indexed by a 1-based index in the `GetBlockTemplateResult.transactions`
    /// list
    pub depends: Vec<u32>,
    // The transaction fee
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub fee: Amount,
}

impl GetBlockTemplateResultTransaction {
    pub fn transaction(&self) -> Result<Transaction, encode::Error> {
        encode::deserialize(&self.raw_tx)
    }
}

/// Enum to representing mutable parts of the block template.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateResulMutations {
    /// The client is allowed to modify the time in the header of the block
    Time,
    /// The client is allowed to add transactions to the block
    Transactions,
    /// The client is allowed to use the work with other previous blocks.
    /// This implicitly allows removing transactions that are no longer valid.
    /// It also implies adjusting the "height" as necessary.
    #[serde(rename = "prevblock")]
    PreviousBlock,
}

/// Model for decode transaction
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct DecodeRawTransactionResult {
    pub txid: bitcoin::Txid,
    pub hash: bitcoin::Txid,
    pub size: u32,
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<GetRawTransactionResultVin>,
    pub vout: Vec<GetRawTransactionResultVout>,
}

/// Models the result of "getchaintips"
pub type GetChainTipsResult = Vec<GetChainTipsResultTip>;

/// Models a single chain tip for the result of "getchaintips"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetChainTipsResultTip {
    /// Block height of the chain tip
    pub height: u64,
    /// Header hash of the chain tip
    pub hash: bitcoin::BlockHash,
    /// Length of the branch (number of blocks since the last common block)
    #[serde(rename = "branchlen")]
    pub branch_length: u32,
    /// Status of the tip as seen by the node
    pub status: GetChainTipsResultStatus,
}

#[derive(Copy, Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum GetChainTipsResultStatus {
    /// The branch contains at least one invalid block
    Invalid,
    /// Not all blocks for this branch are available, but the headers are valid
    #[serde(rename = "headers-only")]
    HeadersOnly,
    /// All blocks are available for this branch, but they were never fully validated
    #[serde(rename = "valid-headers")]
    ValidHeaders,
    /// This branch is not part of the active chain, but is fully validated
    #[serde(rename = "valid-fork")]
    ValidFork,
    /// This is the tip of the active main chain, which is certainly valid
    Active,
}

// Custom types for input arguments.


/// A wrapper around bitcoin::EcdsaSighashType that will be serialized
/// according to what the RPC expects.
pub struct SigHashType(bitcoin::sighash::EcdsaSighashType);

impl From<bitcoin::sighash::EcdsaSighashType> for SigHashType {
    fn from(sht: bitcoin::sighash::EcdsaSighashType) -> SigHashType {
        SigHashType(sht)
    }
}

impl serde::Serialize for SigHashType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self.0 {
            bitcoin::sighash::EcdsaSighashType::All => "ALL",
            bitcoin::sighash::EcdsaSighashType::None => "NONE",
            bitcoin::sighash::EcdsaSighashType::Single => "SINGLE",
            bitcoin::sighash::EcdsaSighashType::AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
            bitcoin::sighash::EcdsaSighashType::NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
            bitcoin::sighash::EcdsaSighashType::SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
        })
    }
}

// Used for createrawtransaction argument.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CreateRawTransactionInput {
    pub txid: bitcoin::Txid,
    pub vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
}

/// Used to represent UTXO set hash type
#[derive(Clone, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TxOutSetHashType {
    HashSerialized2,
    Muhash,
    None,
}

/// Used to specify a block hash or a height
#[derive(Clone, Serialize, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum HashOrHeight {
    BlockHash(bitcoin::BlockHash),
    Height(u64),
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetTxOutSetInfoResult {
    /// The block height (index) of the returned statistics
    pub height: u64,
    /// The hash of the block at which these statistics are calculated
    #[serde(rename = "bestblock")]
    pub best_block: bitcoin::BlockHash,
    /// The number of transactions with unspent outputs
    pub transactions: u64,
    /// The number of unspent transaction outputs
    #[serde(rename = "txouts")]
    pub tx_outs: u64,
    /// A meaningless metric for UTXO set size
    pub bogosize: u64,
    /// The serialized hash
    pub hash_serialized: sha256::Hash,
    /// The estimated size of the chainstate on disk
    pub disk_size: u64,
    /// The total amount
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub total_amount: Amount,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetTotalsResult {
    /// Total bytes received
    #[serde(rename = "totalbytesrecv")]
    pub total_bytes_recv: u64,
    /// Total bytes sent
    #[serde(rename = "totalbytessent")]
    pub total_bytes_sent: u64,
    /// Current UNIX time in milliseconds
    #[serde(rename = "timemillis")]
    pub time_millis: u64,
    /// Upload target statistics
    #[serde(rename = "uploadtarget")]
    pub upload_target: GetNetTotalsResultUploadTarget,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetTotalsResultUploadTarget {
    /// Length of the measuring timeframe in seconds
    #[serde(rename = "timeframe")]
    pub time_frame: u64,
    /// Target in bytes
    pub target: u64,
    /// True if target is reached
    pub target_reached: bool,
    /// True if serving historical blocks
    pub serve_historical_blocks: bool,
    /// Bytes left in current time cycle
    pub bytes_left_in_cycle: u64,
    /// Seconds left in current time cycle
    pub time_left_in_cycle: u64,
}

// Custom deserializer functions.

/// deserialize_hex_array_opt deserializes a vector of hex-encoded byte arrays.
fn deserialize_hex_array_opt<'de, D>(deserializer: D) -> Result<Option<Vec<Vec<u8>>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    //TODO(stevenroose) Revisit when issue is fixed:
    // https://github.com/serde-rs/serde/issues/723

    let v: Vec<String> = Vec::deserialize(deserializer)?;
    let mut res = Vec::new();
    for h in v.into_iter() {
        res.push(FromHex::from_hex(&h).map_err(D::Error::custom)?);
    }
    Ok(Some(res))
}

/// deserialize_bip70_network deserializes a Bitcoin Core network according to BIP70
/// The accepted input variants are: {"main", "test", "signet", "regtest"}
fn deserialize_bip70_network<'de, D>(deserializer: D) -> Result<Network, D::Error> 
where
    D: serde::Deserializer<'de>,
{
    struct NetworkVisitor;
    impl<'de> serde::de::Visitor<'de> for NetworkVisitor {
        type Value = Network;

        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
            Network::from_core_arg(s)
                .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(s), &"bitcoin network encoded as a string"))
        }

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "bitcoin network encoded as a string")
        }
    }

    deserializer.deserialize_str(NetworkVisitor)
}
