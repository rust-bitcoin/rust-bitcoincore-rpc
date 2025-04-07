//! # Rust Client for Bitcoin SV API
//!
//! This is a client library for the Bitcoin SV JSON-RPC API.
//!
//! This library is not expected to be used directly, it is a sub-component of the bitcoinsv-rpc crate.
//! You probably want the bitcoinsv-rpc crate.

#![crate_name = "bitcoinsv_rpc_json"]
#![crate_type = "rlib"]

extern crate alloc;
extern crate serde;
extern crate serde_json;
use bitcoinsv::bitcoin::{BlockHash, BlockchainId, MerkleRoot, Tx, TxHash};
use bitcoinsv::util::Amount;
use hex::FromHex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

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

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetNetworkInfoResult {
    pub version: u32,
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
    #[serde(rename = "relayfee")]
    pub relay_fee: f64,
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

#[cfg(test)]
mod ninfo_tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_deserialize_get_network_info_result() {
        let json_data = r#"
            {
              "version": 101001600,
              "subversion": "/Bitcoin SV:1.0.16/",
              "protocolversion": 70016,
              "localservices": "0000000000000021",
              "localrelay": true,
              "timeoffset": 0,
              "txnpropagationfreq": 250,
              "txnpropagationqlen": 0,
              "networkactive": true,
              "connections": 129,
              "addresscount": 38071,
              "streampolicies": "BlockPriority,Default",
              "networks": [
                {
                  "name": "ipv4",
                  "limited": false,
                  "reachable": true,
                  "proxy": "",
                  "proxy_randomize_credentials": false
                },
                {
                  "name": "ipv6",
                  "limited": false,
                  "reachable": true,
                  "proxy": "",
                  "proxy_randomize_credentials": false
                }
              ],
              "relayfee": 0.00000000,
              "minconsolidationfactor": 20,
              "maxconsolidationinputscriptsize": 150,
              "minconfconsolidationinput": 6,
              "minconsolidationinputmaturity": 6,
              "acceptnonstdconsolidationinput": false,
              "localaddresses": [
                {
                  "address": "192.168.78.4",
                  "port": 8333,
                  "score": 16651
                }
              ],
              "warnings": ""
            }
        "#;
        let result: GetNetworkInfoResult = serde_json::from_str(json_data).unwrap();

        assert_eq!(result.version, 101001600);
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockResultStatus {
    pub validity: String,
    pub data: bool,
    pub undo: bool,
    pub failed: bool,
    #[serde(rename = "parent failed")]
    pub parent_failed: bool,
    #[serde(rename = "disk meta")]
    pub disk_meta: bool,
    #[serde(rename = "soft reject")]
    pub soft_reject: bool,
    #[serde(rename = "double spend")]
    pub double_spend: bool,
    #[serde(rename = "soft consensus frozen")]
    pub soft_consensus_frozen: bool,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockResult {
    pub tx: Vec<TxHash>,
    pub hash: BlockHash,
    pub confirmations: i32,
    pub size: usize,
    pub height: usize,
    pub version: i32,
    #[serde(default, rename = "versionHex", with = "crate::serde_hex")]
    pub version_hex: Vec<u8>,
    pub merkleroot: MerkleRoot,
    pub num_tx: u64,
    pub time: u64,
    pub mediantime: Option<u64>,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    #[serde(with = "crate::serde_hex")]
    #[serde(rename = "chainwork")]
    pub chain_work: Vec<u8>,
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: Option<BlockHash>,
    // todo: isnt this a problem? couldn't there be multiple next blocks in the case of a fork?
    #[serde(rename = "nextblockhash")]
    pub next_block_hash: Option<BlockHash>,
    pub status: GetBlockResultStatus,
}

#[cfg(test)]
mod getblock_tests {
    use super::*;
    use approx::assert_relative_eq;

    #[test]
    fn test_deserialize_get_block_result() {
        let json_data = r#"
            {
              "tx": [
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
              ],
              "hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
              "confirmations": 1,
              "size": 285,
              "height": 0,
              "version": 1,
              "versionHex": "00000001",
              "merkleroot": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
              "num_tx": 1,
              "time": 1296688602,
              "mediantime": 1296688602,
              "nonce": 2,
              "bits": "207fffff",
              "difficulty": 4.656542373906925e-10,
              "chainwork": "0000000000000000000000000000000000000000000000000000000000000002",
              "status": {
                "validity": "transactions",
                "data": true,
                "undo": false,
                "failed": false,
                "parent failed": false,
                "disk meta": true,
                "soft reject": false,
                "double spend": false,
                "soft consensus frozen": false
              }
            }
        "#;

        let result: GetBlockResult = serde_json::from_str(json_data).unwrap();

        assert_eq!(result.confirmations, 1);
        assert_relative_eq!(result.difficulty, 4.656542373906925e-10, epsilon = 1e-8);
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockHeaderResult {
    pub hash: BlockHash,
    pub confirmations: i32,
    pub size: u64,
    pub height: u64,
    pub version: u32,
    #[serde(default, rename = "versionHex", with = "crate::serde_hex::opt")]
    pub version_hex: Option<Vec<u8>>,
    #[serde(rename = "merkleroot")]
    pub merkle_root: MerkleRoot,
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
    pub previous_block_hash: Option<BlockHash>,
    // todo: is this a problem? won't it return multiple hashe's if there is a fork?
    #[serde(rename = "nextblockhash")]
    pub next_block_hash: Option<BlockHash>,
    pub status: GetBlockResultStatus,
    #[serde(rename = "tx")]
    pub coinbase_tx: Option<Vec<GetRawTransactionResult>>, // its a vector but it only has one value
    #[serde(rename = "merkleproof")]
    pub coinbase_merkle_proof: Option<Vec<MerkleRoot>>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockStatsResult {
    #[serde(rename = "avgfee")]
    pub avg_fee: Amount,
    #[serde(rename = "avgfeerate")]
    pub avg_fee_rate: Amount,
    #[serde(rename = "avgtxsize")]
    pub avg_tx_size: u32,
    #[serde(rename = "blockhash")]
    pub block_hash: BlockHash,
    pub height: u64,
    pub ins: u64,
    #[serde(rename = "maxfee")]
    pub max_fee: Amount,
    #[serde(rename = "maxfeerate")]
    pub max_fee_rate: Amount,
    #[serde(rename = "maxtxsize")]
    pub max_tx_size: u32,
    #[serde(rename = "medianfee")]
    pub median_fee: Amount,
    #[serde(rename = "mediantime")]
    pub median_time: u64,
    #[serde(rename = "mediantxsize")]
    pub median_tx_size: u32,
    #[serde(rename = "minfee")]
    pub min_fee: Amount,
    #[serde(rename = "minfeerate")]
    pub min_fee_rate: Amount,
    #[serde(rename = "mintxsize")]
    pub min_tx_size: u32,
    pub outs: usize,
    pub subsidy: Amount,
    pub time: u64,
    pub total_out: Amount,
    pub total_size: usize,
    #[serde(rename = "totalfee")]
    pub total_fee: Amount,
    pub txs: usize,
    pub utxo_increase: i32,
    pub utxo_size_inc: i32,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockStatsResultPartial {
    #[serde(default, rename = "avgfee", skip_serializing_if = "Option::is_none")]
    pub avg_fee: Option<Amount>,
    #[serde(default, rename = "avgfeerate", skip_serializing_if = "Option::is_none")]
    pub avg_fee_rate: Option<Amount>,
    #[serde(default, rename = "avgtxsize", skip_serializing_if = "Option::is_none")]
    pub avg_tx_size: Option<u32>,
    #[serde(default, rename = "blockhash", skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<BlockHash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ins: Option<usize>,
    #[serde(default, rename = "maxfee", skip_serializing_if = "Option::is_none")]
    pub max_fee: Option<Amount>,
    #[serde(default, rename = "maxfeerate", skip_serializing_if = "Option::is_none")]
    pub max_fee_rate: Option<Amount>,
    #[serde(default, rename = "maxtxsize", skip_serializing_if = "Option::is_none")]
    pub max_tx_size: Option<u32>,
    #[serde(default, rename = "medianfee", skip_serializing_if = "Option::is_none")]
    pub median_fee: Option<Amount>,
    #[serde(default, rename = "mediantime", skip_serializing_if = "Option::is_none")]
    pub median_time: Option<u64>,
    #[serde(default, rename = "mediantxsize", skip_serializing_if = "Option::is_none")]
    pub median_tx_size: Option<u32>,
    #[serde(default, rename = "minfee", skip_serializing_if = "Option::is_none")]
    pub min_fee: Option<Amount>,
    #[serde(default, rename = "minfeerate", skip_serializing_if = "Option::is_none")]
    pub min_fee_rate: Option<Amount>,
    #[serde(default, rename = "mintxsize", skip_serializing_if = "Option::is_none")]
    pub min_tx_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outs: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsidy: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_out: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_size: Option<usize>,
    #[serde(default, rename = "totalfee", skip_serializing_if = "Option::is_none")]
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
    pub chain: BlockchainId,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVinScriptSig {
    pub asm: String,
    #[serde(with = "crate::serde_hex")]
    pub hex: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVin {
    pub sequence: u32,
    /// The raw scriptSig in case of a coinbase tx.
    #[serde(default, with = "crate::serde_hex::opt")]
    pub coinbase: Option<Vec<u8>>,
    /// Not provided for coinbase txs.
    pub txid: Option<TxHash>,
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

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVout {
    pub value: Amount,
    pub n: u32,
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResult {
    #[serde(with = "crate::serde_hex")]
    pub hex: Vec<u8>,
    pub txid: TxHash,
    pub hash: TxHash,
    pub version: u32,
    pub size: usize,
    pub locktime: u32,
    pub vin: Vec<GetRawTransactionResultVin>,
    pub vout: Vec<GetRawTransactionResultVout>,
    #[serde(rename = "blockhash")]
    pub block_hash: Option<BlockHash>,
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

    pub fn transaction(&self) -> Result<Tx, bitcoinsv::Error> {
        let tx = Tx::from_hex(&self.hex)?;
        Ok(tx)
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTxOutResult {
    pub bestblock: BlockHash,
    pub confirmations: u32,
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
    pub chain: BlockchainId,
    /// The current number of blocks processed in the server
    pub blocks: u64,
    /// The current number of headers we have validated
    pub headers: u64,
    /// The hash of the currently best block
    #[serde(rename = "bestblockhash")]
    pub best_block_hash: BlockHash,
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
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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
    pub mempool_min_fee: Amount,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetMempoolEntryResult {
    pub size: u64,
    /// Transaction fee in BSV
    pub fee: Amount,
    #[serde(rename = "modifiedfee")]
    pub modified_fee: Amount,
    /// Local time transaction entered pool in seconds since 1 Jan 1970 GMT
    pub time: u64,
    /// Block height when transaction entered pool
    pub height: u64,
    /// Unconfirmed transactions used as inputs for this transaction
    pub depends: Vec<TxHash>,
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

/// Model for decode transaction
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct DecodeRawTransactionResult {
    pub txid: TxHash,
    pub hash: TxHash,
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
    pub hash: BlockHash,
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

// Used for createrawtransaction argument.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CreateRawTransactionInput {
    pub txid: TxHash,
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
    BlockHash(BlockHash),
    Height(u64),
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetTxOutSetInfoResult {
    /// The block height (index) of the returned statistics
    pub height: u64,
    /// The hash of the block at which these statistics are calculated
    #[serde(rename = "bestblock")]
    pub best_block: BlockHash,
    /// The number of transactions with unspent outputs
    pub transactions: u64,
    /// The number of unspent transaction outputs
    #[serde(rename = "txouts")]
    pub tx_outs: u64,
    /// A meaningless metric for UTXO set size
    pub bogosize: u64,
    /// The serialized hash
    pub hash_serialized: BlockHash,
    /// The estimated size of the chainstate on disk
    pub disk_size: u64,
    /// The total amount
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
