// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Rust Client for Dash Core API
//!
//! This is a client library for the Dash Core JSON-RPC API.
//!

#![crate_name = "dashcore_rpc_json"]
#![crate_type = "rlib"]

pub extern crate dashcore;
#[allow(unused)]
#[macro_use] // `macro_use` is needed for v1.24.0 compilation.
extern crate serde;
extern crate serde_json;
extern crate serde_with;

use hex;
use serde_repr::*;
use std::collections::{HashMap};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;

use dashcore::consensus::encode;
use dashcore::hashes::hex::{FromHex, ToHex};
use dashcore::hashes::sha256;
use dashcore::util::{bip158, bip32};
use dashcore::{
    Address, Amount, BlockHash, PrivateKey, ProTxHash, PublicKey, QuorumHash, Script, SignedAmount,
    Transaction,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use serde_with::{serde_as, Bytes, DisplayFromStr};

//TODO(stevenroose) consider using a Time type

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetworkInfoResultNetwork {
    pub name: String,
    pub limited: bool,
    pub reachable: bool,
    pub proxy: String,
    pub proxy_randomize_credentials: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetworkInfoResultAddress {
    pub address: String,
    pub port: usize,
    pub score: usize,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetworkInfoResult {
    pub version: usize,
    #[serde(rename = "buildversion")]
    pub build_version: String,
    pub subversion: String,
    #[serde(rename = "protocolversion")]
    pub protocol_version: usize,
    #[serde(rename = "localservices")]
    pub local_services: String,
    #[serde(rename = "localservicesnames")]
    pub local_services_names: Vec<String>,
    #[serde(rename = "localrelay")]
    pub local_relay: bool,
    #[serde(rename = "timeoffset")]
    pub time_offset: isize,
    #[serde(rename = "networkactive")]
    pub network_active: bool,
    pub connections: usize,
    #[serde(rename = "inboundconnections")]
    pub inbound_connections: usize,
    #[serde(rename = "outboundconnections")]
    pub outbound_connections: usize,
    #[serde(rename = "mnconnections")]
    pub mn_connections: usize,
    #[serde(rename = "inboundmnconnections")]
    pub inbound_mn_connections: usize,
    #[serde(rename = "outboundmnconnections")]
    pub outbound_mn_connections: usize,
    #[serde(rename = "socketevents")]
    pub socket_events: String,
    pub networks: Vec<GetNetworkInfoResultNetwork>,
    #[serde(rename = "relayfee", with = "dashcore::util::amount::serde::as_btc")]
    pub relay_fee: Amount,
    #[serde(rename = "incrementalfee", with = "dashcore::util::amount::serde::as_btc")]
    pub incremental_fee: Amount,
    #[serde(rename = "localaddresses")]
    pub local_addresses: Vec<GetNetworkInfoResultAddress>,
    pub warnings: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMultiSigAddressResult {
    pub address: Address,
    pub redeem_script: Script,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct LoadWalletResult {
    pub name: String,
    pub warning: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetWalletInfoResult {
    #[serde(rename = "walletname")]
    pub wallet_name: String,
    #[serde(rename = "walletversion")]
    pub wallet_version: u32,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub balance: Amount,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub coinjoin_balance: Amount,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub unconfirmed_balance: Amount,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub immature_balance: Amount,
    #[serde(rename = "txcount")]
    pub tx_count: usize,
    #[serde(rename = "timefirstkey")]
    pub time_first_key: u32,
    #[serde(rename = "keypoololdest")]
    pub keypool_oldest: usize,
    #[serde(rename = "keypoolsize")]
    pub keypool_size: usize,
    #[serde(rename = "keypoolsize_hd_internal")]
    pub keypool_size_hd_internal: Option<usize>,
    pub keys_left: usize,
    pub unlocked_until: Option<u64>,
    #[serde(rename = "paytxfee")]
    pub pay_tx_fee: u32,
    #[serde(rename = "hdchainid", deserialize_with = "deserialize_hex_opt")]
    pub hd_chainid: Option<Vec<u8>>,
    #[serde(rename = "hdaccountcount")]
    pub hd_account_count: Option<u32>,
    // disable until to get specification about where these fields should be
    // #[serde(rename = "hdaccountcountindex")]
    // pub hd_account_count_index: Option<u32>,
    // #[serde(rename = "hdexternalkeyindex")]
    // pub hd_external_key_index: Option<u32>,
    // #[serde(rename = "hdinternalkeyindex")]
    // pub hd_internal_key_index: Option<u32>,
    pub scanning: Option<ScanningDetails>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum ScanningDetails {
    Scanning {
        duration: usize,
        progress: f32,
    },
    /// The bool in this field will always be false.
    NotScanning(bool),
}

impl Eq for ScanningDetails {}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CoinbaseTxDetails {
    pub version: usize,
    pub height: i32,
    #[serde(rename = "merkleRootMNList", with = "hex")]
    merkle_root_mn_list: Vec<u8>,
    #[serde(rename = "merkleRootQuorums", with = "hex")]
    merkle_root_quorums: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBestChainLockResult {
    pub blockhash: BlockHash,
    pub height: u32,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
    pub known_block: bool,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockResult {
    pub hash: dashcore::BlockHash,
    pub confirmations: i32,
    pub size: usize,
    pub strippedsize: Option<usize>,
    pub height: usize,
    pub version: i32,
    #[serde(default, deserialize_with = "deserialize_hex_opt")]
    pub version_hex: Option<Vec<u8>>,
    pub merkleroot: dashcore::TxMerkleNode,
    pub tx: Vec<dashcore::Txid>,
    pub cb_tx: CoinbaseTxDetails,
    pub time: usize,
    pub mediantime: usize,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    pub chainwork: Vec<u8>,
    pub n_tx: usize,
    pub previousblockhash: Option<dashcore::BlockHash>,
    pub nextblockhash: Option<dashcore::BlockHash>,
    pub chainlock: bool,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResult {
    pub hash: dashcore::BlockHash,
    pub confirmations: i32,
    pub height: usize,
    pub version: i32,
    #[serde(default, with = "hex")]
    pub version_hex: Vec<u8>,
    #[serde(rename = "merkleroot")]
    pub merkle_root: dashcore::TxMerkleNode,
    pub time: usize,
    #[serde(rename = "mediantime")]
    pub median_time: Option<usize>,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    #[serde(with = "hex")]
    pub chainwork: Vec<u8>,
    pub n_tx: usize,
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: Option<dashcore::BlockHash>,
    #[serde(rename = "nextblockhash")]
    pub next_block_hash: Option<dashcore::BlockHash>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockStatsResult {
    #[serde(rename = "avgfee", with = "dashcore::util::amount::serde::as_sat")]
    pub avg_fee: Amount,
    #[serde(rename = "avgfeerate", with = "dashcore::util::amount::serde::as_sat")]
    pub avg_fee_rate: Amount,
    #[serde(rename = "avgtxsize")]
    pub avg_tx_size: u32,
    #[serde(rename = "blockhash")]
    pub block_hash: dashcore::BlockHash,
    #[serde(rename = "feerate_percentiles")]
    pub fee_rate_percentiles: FeeRatePercentiles,
    pub height: u32,
    pub ins: usize,
    #[serde(rename = "maxfee", with = "dashcore::util::amount::serde::as_sat")]
    pub max_fee: Amount,
    #[serde(rename = "maxfeerate", with = "dashcore::util::amount::serde::as_sat")]
    pub max_fee_rate: Amount,
    #[serde(rename = "maxtxsize")]
    pub max_tx_size: u32,
    #[serde(rename = "medianfee", with = "dashcore::util::amount::serde::as_sat")]
    pub median_fee: Amount,
    #[serde(rename = "mediantime")]
    pub median_time: u64,
    #[serde(rename = "mediantxsize")]
    pub median_tx_size: u32,
    #[serde(rename = "minfee", with = "dashcore::util::amount::serde::as_sat")]
    pub min_fee: Amount,
    #[serde(rename = "minfeerate", with = "dashcore::util::amount::serde::as_sat")]
    pub min_fee_rate: Amount,
    #[serde(rename = "mintxsize")]
    pub min_tx_size: u32,
    pub outs: usize,
    #[serde(with = "dashcore::util::amount::serde::as_sat")]
    pub subsidy: Amount,
    pub time: u64,
    #[serde(with = "dashcore::util::amount::serde::as_sat")]
    pub total_out: Amount,
    #[serde(rename = "total_size")]
    pub total_size: usize,
    #[serde(rename = "totalfee", with = "dashcore::util::amount::serde::as_sat")]
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
        with = "dashcore::util::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub avg_fee: Option<Amount>,
    #[serde(
        default,
        rename = "avgfeerate",
        with = "dashcore::util::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub avg_fee_rate: Option<Amount>,
    #[serde(default, rename = "avgtxsize", skip_serializing_if = "Option::is_none")]
    pub avg_tx_size: Option<u32>,
    #[serde(default, rename = "blockhash", skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<dashcore::BlockHash>,
    #[serde(default, rename = "feerate_percentiles", skip_serializing_if = "Option::is_none")]
    pub fee_rate_percentiles: Option<FeeRatePercentiles>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ins: Option<usize>,
    #[serde(
        default,
        rename = "maxfee",
        with = "dashcore::util::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_fee: Option<Amount>,
    #[serde(
        default,
        rename = "maxfeerate",
        with = "dashcore::util::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_fee_rate: Option<Amount>,
    #[serde(default, rename = "maxtxsize", skip_serializing_if = "Option::is_none")]
    pub max_tx_size: Option<u32>,
    #[serde(
        default,
        rename = "medianfee",
        with = "dashcore::util::amount::serde::as_sat::opt",
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
        with = "dashcore::util::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_fee: Option<Amount>,
    #[serde(
        default,
        rename = "minfeerate",
        with = "dashcore::util::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_fee_rate: Option<Amount>,
    #[serde(default, rename = "mintxsize", skip_serializing_if = "Option::is_none")]
    pub min_tx_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outs: Option<usize>,
    #[serde(
        default,
        with = "dashcore::util::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub subsidy: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<u64>,
    #[serde(
        default,
        with = "dashcore::util::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub total_out: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_size: Option<usize>,
    #[serde(
        default,
        rename = "totalfee",
        with = "dashcore::util::amount::serde::as_sat::opt",
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

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct FeeRatePercentiles {
    #[serde(with = "dashcore::util::amount::serde::as_sat", rename = "10th_percentile_feerate")]
    pub fr_10th: Amount,
    #[serde(with = "dashcore::util::amount::serde::as_sat", rename = "25th_percentile_feerate")]
    pub fr_25th: Amount,
    #[serde(with = "dashcore::util::amount::serde::as_sat", rename = "50th_percentile_feerate")]
    pub fr_50th: Amount,
    #[serde(with = "dashcore::util::amount::serde::as_sat", rename = "75th_percentile_feerate")]
    pub fr_75th: Amount,
    #[serde(with = "dashcore::util::amount::serde::as_sat", rename = "90th_percentile_feerate")]
    pub fr_90th: Amount,
}

#[derive(Clone)]
pub enum BlockStatsFields {
    AverageFee,
    AverageFeeRate,
    AverageTxSize,
    BlockHash,
    FeeRatePercentiles,
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
    SegWitTotalSize,
    SegWitTotalWeight,
    SegWitTxs,
    Time,
    TotalOut,
    TotalSize,
    TotalWeight,
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
            BlockStatsFields::FeeRatePercentiles => "feerate_percentiles",
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
            BlockStatsFields::SegWitTotalSize => "swtotal_size",
            BlockStatsFields::SegWitTotalWeight => "swtotal_weight",
            BlockStatsFields::SegWitTxs => "swtxs",
            BlockStatsFields::Time => "time",
            BlockStatsFields::TotalOut => "total_out",
            BlockStatsFields::TotalSize => "total_size",
            BlockStatsFields::TotalWeight => "total_weight",
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
    #[serde(rename = "currentblockweight")]
    pub current_block_weight: Option<u64>,
    #[serde(rename = "currentblocktx")]
    pub current_block_tx: Option<usize>,
    pub difficulty: f64,
    #[serde(rename = "networkhashps")]
    pub network_hash_ps: f64,
    #[serde(rename = "pooledtx")]
    pub pooled_tx: usize,
    pub chain: String,
    pub warnings: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVinScriptSig {
    pub asm: String,
    pub hex: Vec<u8>,
}

impl GetRawTransactionResultVinScriptSig {
    pub fn script(&self) -> Result<Script, encode::Error> {
        Ok(Script::from(self.hex.clone()))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVin {
    pub txid: Option<String>,
    pub vout: Option<u32>,
    pub script_sig: Option<GetRawTransactionResultVinScriptSig>,
    #[serde(deserialize_with = "deserialize_hex_opt")]
    pub coinbase: Option<Vec<u8>>,
    #[serde(with = "dashcore::util::amount::serde::as_btc::opt")]
    pub value: Option<Amount>,
    #[serde(rename = "valueSat")]
    pub value_sat: Option<u32>,
    pub addresses: Vec<String>,
    pub sequence: u32,
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
    #[serde(with = "hex")]
    pub hex: Vec<u8>,
    #[serde(rename = "reqSigs")]
    pub req_sigs: Option<usize>,
    #[serde(rename = "type")]
    pub script_type: Option<ScriptPubkeyType>,
    pub addresses: Option<Vec<Address>>,
}

impl GetRawTransactionResultVoutScriptPubKey {
    pub fn script(&self) -> Result<Script, encode::Error> {
        Ok(Script::from(self.hex.clone()))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVout {
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub value: Amount,
    #[serde(rename = "valueSat")]
    pub value_sat: u32,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResult {
    #[serde(rename = "in_active_chain")]
    pub in_active_chain: bool,
    pub txid: dashcore::Txid,
    pub size: usize,
    pub version: u32,
    #[serde(rename = "type")]
    pub tx_type: u32,
    pub locktime: u32,
    pub vin: Vec<GetRawTransactionResultVin>,
    pub vout: Vec<GetRawTransactionResultVout>,
    #[serde(rename = "extraPayloadSize")]
    pub extra_payload_size: u32,
    #[serde(rename = "extraPayload", deserialize_with = "deserialize_hex_opt")]
    pub extra_payload: Option<Vec<u8>>,
    #[serde(with = "hex")]
    pub hex: Vec<u8>,
    pub blockhash: Option<dashcore::BlockHash>,
    pub height: Option<u32>,
    pub confirmations: u32,
    pub time: Option<usize>,
    pub blocktime: Option<usize>,
    pub instantlock: bool,
    pub instantlock_internal: bool,
    pub chainlock: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockFilterResult {
    pub header: dashcore::FilterHash,
    #[serde(with = "hex")]
    pub filter: Vec<u8>,
}

impl GetBlockFilterResult {
    /// Get the filter.
    /// Note that this copies the underlying filter data. To prevent this,
    /// use [into_filter] instead.
    pub fn to_filter(&self) -> bip158::BlockFilter {
        bip158::BlockFilter::new(&self.filter)
    }

    /// Convert the result in the filter type.
    pub fn into_filter(self) -> bip158::BlockFilter {
        bip158::BlockFilter {
            content: self.filter,
        }
    }
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

/// Enum to represent the BIP125 replaceable status for a transaction.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Bip125Replaceable {
    Yes,
    No,
    Unknown,
}

/// Enum to represent the category of a transaction.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetTransactionResultDetailCategory {
    Send,
    Receive,
    Generate,
    Immature,
    Orphan,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetTransactionResultDetail {
    #[serde(rename = "involvesWatchonly")]
    pub involves_watchonly: bool,
    pub address: Option<Address>,
    pub category: GetTransactionResultDetailCategory,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub amount: SignedAmount,
    pub label: Option<String>,
    pub vout: u32,
    #[serde(default, with = "dashcore::util::amount::serde::as_btc::opt")]
    pub fee: Option<SignedAmount>,
    pub abandoned: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct WalletTxInfo {
    pub confirmations: i32,
    pub blockhash: Option<BlockHash>,
    pub blockindex: Option<usize>,
    pub blocktime: Option<u64>,
    pub blockheight: Option<u32>,
    pub txid: dashcore::Txid,
    pub time: u64,
    pub timereceived: u64,
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: Bip125Replaceable,
    /// Conflicting transaction ids
    #[serde(rename = "walletconflicts")]
    pub wallet_conflicts: Vec<dashcore::Txid>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetTransactionResult {
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub amount: SignedAmount,
    #[serde(default, with = "dashcore::util::amount::serde::as_btc::opt")]
    pub fee: Option<SignedAmount>,
    pub confirmations: i32,
    pub instantlock: bool,
    pub instantlock_internal: bool,
    pub chainlock: bool,
    pub generated: bool,
    pub blockhash: Option<BlockHash>,
    pub blockindex: Option<u32>,
    pub blocktime: Option<u32>,
    pub txid: Option<dashcore::Txid>,

    pub time: u32,
    pub timereceived: u32,
    pub abandoned: Option<bool>,
    pub comment: Option<String>,
    pub to: Option<String>,
    #[serde(rename = "DS")]
    pub ds: Option<bool>,
    pub details: Vec<GetTransactionResultDetail>,
    #[serde(with = "hex")]
    pub hex: Vec<u8>,
}

impl GetTransactionResult {
    pub fn transaction(&self) -> Result<Transaction, encode::Error> {
        Ok(encode::deserialize(&self.hex)?)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct ListTransactionResult {
    #[serde(flatten)]
    pub info: WalletTxInfo,
    #[serde(flatten)]
    pub detail: GetTransactionResultDetail,

    pub trusted: Option<bool>,
    pub comment: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct ListSinceBlockResult {
    pub transactions: Vec<ListTransactionResult>,
    #[serde(default)]
    pub removed: Vec<ListTransactionResult>,
    pub lastblock: BlockHash,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTxOutResult {
    pub bestblock: BlockHash,
    pub confirmations: u32,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub value: Amount,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
    pub coinbase: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentQueryOptions {
    #[serde(
        rename = "minimumAmount",
        with = "dashcore::util::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_amount: Option<Amount>,
    #[serde(
        rename = "maximumAmount",
        with = "dashcore::util::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub maximum_amount: Option<Amount>,
    #[serde(rename = "maximumCount", skip_serializing_if = "Option::is_none")]
    pub maximum_count: Option<usize>,
    #[serde(
        rename = "minimumSumAmount",
        with = "dashcore::util::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_sum_amount: Option<Amount>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentResultEntry {
    pub txid: dashcore::Txid,
    pub vout: u32,
    pub address: Option<Address>,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: Script,
    #[serde(rename = "redeemScript")]
    pub redeem_script: Option<Script>,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub amount: Amount,
    pub confirmations: u32,
    pub spendable: bool,
    pub solvable: bool,
    #[serde(rename = "desc")]
    pub descriptor: Option<String>,
    pub reused: Option<bool>,
    pub safe: bool,
    pub coinjoin_rounds: u32,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListReceivedByAddressResult {
    #[serde(default, rename = "involvesWatchonly")]
    pub involved_watch_only: bool,
    pub address: Address,
    pub account: String,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub amount: Amount,
    pub confirmations: u32,
    pub label: String,
    pub txids: Vec<dashcore::Txid>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct SignRawTransactionResult {
    #[serde(with = "hex")]
    pub hex: Vec<u8>,
    pub complete: bool,
}

impl SignRawTransactionResult {
    pub fn transaction(&self) -> Result<Transaction, encode::Error> {
        Ok(encode::deserialize(&self.hex)?)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TestMempoolAcceptResult {
    pub txid: dashcore::Txid,
    pub allowed: bool,
    #[serde(rename = "reject-reason")]
    pub reject_reason: String,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Bip9SoftforkStatus {
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Bip9SoftforkStatistics {
    pub period: Option<u32>,
    pub threshold: Option<u32>,
    pub elapsed: Option<u32>,
    pub count: Option<u32>,
    pub possible: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Bip9SoftforkInfo {
    pub status: Bip9SoftforkStatus,
    pub bit: Option<u8>,
    // Can be -1 for 0.18.x inactive ones.
    pub start_time: i64,
    pub timeout: u64,
    pub since: u32,
    pub statistics: Option<Bip9SoftforkStatistics>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SoftforkType {
    Buried,
    Bip9,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct SoftforkInfo {
    pub status: Option<bool>,
    pub found: Option<u32>,
    pub required: Option<u32>,
    pub window: Option<u32>,
}

/// Status of a softfork
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Softfork {
    pub id: String,
    pub version: u32,
    pub enforce: Option<SoftforkInfo>,
    pub reject: Option<SoftforkInfo>,
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
    Witness_v0_KeyHash,
    Witness_v0_ScriptHash,
    Witness_v1_Taproot,
    Witness_Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetAddressInfoResultLabelPurpose {
    Send,
    Receive,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum GetAddressInfoResultLabel {
    Simple(String),
    WithPurpose {
        name: String,
        purpose: GetAddressInfoResultLabelPurpose,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetAddressInfoResult {
    pub address: Address,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: Script,
    #[serde(rename = "ismine")]
    pub is_mine: bool,
    #[serde(rename = "iswatchonly")]
    pub is_watchonly: bool,
    pub solvable: bool,
    pub desc: Option<bool>,
    #[serde(rename = "isscript")]
    pub is_script: bool,
    #[serde(rename = "ischange")]
    pub is_change: bool,
    pub script: Option<ScriptPubkeyType>,
    /// The redeemscript for the p2sh address.
    #[serde(deserialize_with = "deserialize_hex_opt")]
    pub hex: Option<Vec<u8>>,
    pub pubkeys: Option<Vec<PublicKey>>,
    pub pubkey: Option<PublicKey>,
    #[serde(rename = "sigsrequired")]
    pub signatures_required: Option<usize>,
    #[serde(rename = "iscompressed")]
    pub is_compressed: Option<bool>,
    /// Deprecated in v0.20.0. See `labels` field instead.
    #[deprecated(note = "since Core v0.20.0")]
    pub label: Option<String>,
    pub timestamp: Option<u64>,
    #[serde(rename = "hdchainid")]
    pub hd_chain_id: Option<String>,
    #[serde(rename = "hdkeypath")]
    pub hd_key_path: Option<bip32::DerivationPath>,
    #[serde(rename = "hdmasterfingerprint")]
    pub hd_master_fingerprint: Option<String>,
    pub labels: Vec<GetAddressInfoResultLabel>,
}

/// Models the result of "getblockchaininfo"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetBlockchainInfoResult {
    /// Current network name as defined in BIP70 (main, test, regtest)
    pub chain: String,
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
    /// Estimate of whether this node is in Initial Block Download mode
    #[serde(rename = "initialblockdownload")]
    pub initial_block_download: bool,
    /// Total amount of work in active chain, in hexadecimal
    #[serde(with = "hex")]
    pub chainwork: Vec<u8>,
    /// The estimated size of the block and undo files on disk
    pub size_on_disk: u64,
    /// If the blocks are subject to pruning
    pub pruned: bool,
    /// Lowest-height complete block stored (only present if pruning is enabled)
    #[serde(rename = "pruneheight")]
    pub prune_height: Option<u64>,
    /// Whether automatic pruning is enabled (only present if pruning is enabled)
    pub automatic_pruning: Option<bool>,
    /// The target size used by pruning (only present if automatic pruning is enabled)
    pub prune_target_size: Option<u64>,
    /// Status of softforks in progress
    #[serde(default)]
    pub softforks: Vec<Softfork>,
    pub bip9_softforks: HashMap<String, Bip9SoftforkInfo>,
    /// Any network and blockchain warnings.
    pub warnings: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ImportMultiRequestScriptPubkey<'a> {
    Address(&'a Address),
    Script(&'a Script),
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolEntryResult {
    /// Virtual transaction size as defined in BIP 141. This is different from actual serialized
    /// size for witness transactions as witness data is discounted.
    #[serde(alias = "size")]
    pub size: u64,
    /// Transaction weight as defined in BIP 141. Added in Core v0.19.0.
    pub weight: Option<u64>,
    /// Local time transaction entered pool in seconds since 1 Jan 1970 GMT
    pub time: u64,
    /// Block height when transaction entered pool
    pub height: u64,
    /// Number of in-mempool descendant transactions (including this one)
    #[serde(rename = "descendantcount")]
    pub descendant_count: u64,
    /// Virtual transaction size of in-mempool descendants (including this one)
    #[serde(rename = "descendantsize")]
    pub descendant_size: u64,
    /// Number of in-mempool ancestor transactions (including this one)
    #[serde(rename = "ancestorcount")]
    pub ancestor_count: u64,
    /// Virtual transaction size of in-mempool ancestors (including this one)
    #[serde(rename = "ancestorsize")]
    pub ancestor_size: u64,
    /// Hash of serialized transaction, including witness data
    pub wtxid: dashcore::Txid,
    /// Fee information
    pub fees: GetMempoolEntryResultFees,
    /// Unconfirmed transactions used as inputs for this transaction
    pub depends: Vec<dashcore::Txid>,
    /// Unconfirmed transactions spending outputs from this transaction
    #[serde(rename = "spentby")]
    pub spent_by: Vec<dashcore::Txid>,
    /// Whether this transaction could be replaced due to BIP125 (replace-by-fee)
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: bool,
    /// Whether this transaction is currently unbroadcast (initial broadcast not yet acknowledged by any peers)
    /// Added in dashcore Core v0.21
    pub unbroadcast: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolEntryResultFees {
    /// Transaction fee in BTC
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub base: Amount,
    /// Transaction fee with fee deltas used for mining priority in BTC
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub modified: Amount,
    /// Modified fees (see above) of in-mempool ancestors (including this one) in BTC
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub ancestor: Amount,
    /// Modified fees (see above) of in-mempool descendants (including this one) in BTC
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub descendant: Amount,
}

impl<'a> serde::Serialize for ImportMultiRequestScriptPubkey<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ImportMultiRequestScriptPubkey::Address(ref addr) => {
                #[derive(Serialize)]
                struct Tmp<'a> {
                    pub address: &'a Address,
                }
                serde::Serialize::serialize(
                    &Tmp {
                        address: addr,
                    },
                    serializer,
                )
            }
            ImportMultiRequestScriptPubkey::Script(script) => {
                serializer.serialize_str(&script.as_bytes().to_hex())
            }
        }
    }
}

/// A import request for importmulti.
///
/// Note: unlike in dashcored, `timestamp` defaults to 0.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize)]
pub struct ImportMultiRequest<'a> {
    pub timestamp: ImportMultiRescanSince,
    /// If using descriptor, do not also provide address/scriptPubKey, scripts, or pubkeys.
    #[serde(rename = "desc", skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<&'a str>,
    #[serde(rename = "scriptPubKey", skip_serializing_if = "Option::is_none")]
    pub script_pubkey: Option<ImportMultiRequestScriptPubkey<'a>>,
    #[serde(rename = "redeemscript", skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<&'a Script>,
    #[serde(rename = "witnessscript", skip_serializing_if = "Option::is_none")]
    pub witness_script: Option<&'a Script>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub pubkeys: &'a [PublicKey],
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub keys: &'a [PrivateKey],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<(usize, usize)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchonly: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keypool: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct ImportMultiOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rescan: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Copy, Debug)]
pub enum ImportMultiRescanSince {
    Now,
    Timestamp(u64),
}

impl serde::Serialize for ImportMultiRescanSince {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ImportMultiRescanSince::Now => serializer.serialize_str("now"),
            ImportMultiRescanSince::Timestamp(timestamp) => serializer.serialize_u64(timestamp),
        }
    }
}

impl<'de> serde::Deserialize<'de> for ImportMultiRescanSince {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ImportMultiRescanSince;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "unix timestamp or 'now'")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ImportMultiRescanSince::Timestamp(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value == "now" {
                    Ok(ImportMultiRescanSince::Now)
                } else {
                    Err(de::Error::custom(format!(
                        "invalid str '{}', expecting 'now' or unix timestamp",
                        value
                    )))
                }
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

impl Default for ImportMultiRescanSince {
    fn default() -> Self {
        ImportMultiRescanSince::Timestamp(0)
    }
}

impl From<u64> for ImportMultiRescanSince {
    fn from(timestamp: u64) -> Self {
        ImportMultiRescanSince::Timestamp(timestamp)
    }
}

impl From<Option<u64>> for ImportMultiRescanSince {
    fn from(timestamp: Option<u64>) -> Self {
        timestamp.map_or(ImportMultiRescanSince::Now, ImportMultiRescanSince::Timestamp)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ImportMultiResultError {
    pub code: i64,
    pub message: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ImportMultiResultImport {
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: Option<Vec<u8>>,
    pub address: Option<Address>,
    pub timestamp: ImportMultiRescanSince,
    #[serde(rename = "redeemscript")]
    pub redeem_script: Option<String>,
    pub pubkeys: Option<Vec<String>>,
    pub keys: Option<Vec<String>>,
    pub internal: Option<bool>,
    pub watchonly: Option<bool>,
    pub label: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ImportMultiResult {
    pub success: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub error: Option<ImportMultiResultError>,
}

/// Progress toward rejecting pre-softfork blocks
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct RejectStatus {
    /// `true` if threshold reached
    pub status: bool,
}

/// Models the result of "getpeerinfo"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetPeerInfoResult {
    /// Peer index
    pub id: u64,
    /// The IP address and port of the peer
    pub addr: Address,
    /// Bind address of the connection to the peer
    // TODO: use a type for addrbind
    pub addrbind: String,
    /// Local address as reported by the peer
    // TODO: use a type for addrlocal
    pub addrlocal: Option<String>,
    /// Network (ipv4, ipv6, or onion) the peer connected through
    /// Added in Bitcoin Core v0.21
    pub network: Option<GetPeerInfoResultNetwork>,
    /// The services offered
    // TODO: use a type for services
    pub services: String,
    /// Whether peer has asked us to relay transactions to it
    pub relaytxes: bool,
    /// The time in seconds since epoch (Jan 1 1970 GMT) of the last send
    pub lastsend: u64,
    /// The time in seconds since epoch (Jan 1 1970 GMT) of the last receive
    pub lastrecv: u64,
    /// The time in seconds since epoch (Jan 1 1970 GMT) of the last valid transaction received from this peer
    /// Added in Bitcoin Core v0.21
    pub last_transaction: Option<u64>,
    /// The time in seconds since epoch (Jan 1 1970 GMT) of the last block received from this peer
    /// Added in Bitcoin Core v0.21
    pub last_block: Option<u64>,
    /// The total bytes sent
    pub bytessent: u64,
    /// The total bytes received
    pub bytesrecv: u64,
    /// The connection time in seconds since epoch (Jan 1 1970 GMT)
    pub conntime: u64,
    /// The time offset in seconds
    pub timeoffset: i64,
    /// ping time (if available)
    pub pingtime: Option<f64>,
    /// minimum observed ping time (if any at all)
    pub minping: Option<f64>,
    /// ping wait (if non-zero)
    pub pingwait: Option<f64>,
    /// The peer version, such as 70001
    pub version: u64,
    /// The string version
    pub subver: String,
    /// Inbound (true) or Outbound (false)
    pub inbound: bool,
    /// Whether connection was due to `addnode`/`-connect` or if it was an
    /// automatic/inbound connection
    /// Deprecated in Bitcoin Core v0.21
    pub addnode: Option<bool>,
    /// The starting height (block) of the peer
    pub startingheight: i64,
    /// The ban score
    /// Deprecated in Bitcoin Core v0.21
    pub banscore: Option<i64>,
    /// The last header we have in common with this peer
    pub synced_headers: i64,
    /// The last block we have in common with this peer
    pub synced_blocks: i64,
    /// The heights of blocks we're currently asking from this peer
    pub inflight: Vec<u64>,
    /// Whether the peer is whitelisted
    /// Deprecated in Bitcoin Core v0.21
    pub whitelisted: Option<bool>,
    #[serde(rename = "minfeefilter", default, with = "dashcore::util::amount::serde::as_btc::opt")]
    pub min_fee_filter: Option<Amount>,
    /// The total bytes sent aggregated by message type
    pub bytessent_per_msg: HashMap<String, u64>,
    /// The total bytes received aggregated by message type
    pub bytesrecv_per_msg: HashMap<String, u64>,
    /// The type of the connection
    /// Added in Bitcoin Core v0.21
    pub connection_type: Option<GetPeerInfoResultConnectionType>,
}

#[derive(Copy, Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum GetPeerInfoResultNetwork {
    Ipv4,
    Ipv6,
    Onion,
    NotPubliclyRoutable,
    I2p,
    Cjdns,
    Internal,
}

#[derive(Copy, Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum GetPeerInfoResultConnectionType {
    OutboundFullRelay,
    BlockRelayOnly,
    Inbound,
    Manual,
    AddrFetch,
    Feeler,
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
    /// The dashcore server IP and port we're connected to
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
pub struct GetNodeAddressesResult {
    /// Timestamp in seconds since epoch (Jan 1 1970 GMT) keeping track of when the node was last seen
    pub time: u64,
    /// The services offered
    pub services: usize,
    /// The address of the node
    pub address: String,
    /// The port of the node
    pub port: u16,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ListBannedResult {
    pub address: String,
    pub banned_until: u64,
    pub ban_created: u64,
}

/// Models the result of "estimatesmartfee"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EstimateSmartFeeResult {
    /// Estimate fee rate in BTC/kB.
    #[serde(
        default,
        rename = "feerate",
        skip_serializing_if = "Option::is_none",
        with = "dashcore::util::amount::serde::as_btc::opt"
    )]
    pub fee_rate: Option<Amount>,
    /// Errors encountered during processing.
    pub errors: Option<Vec<String>>,
    /// Block number where estimate was found.
    pub blocks: i64,
}

/// Models the result of "waitfornewblock", and "waitforblock"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockRef {
    pub hash: BlockHash,
    pub height: u64,
}

/// Models the result of "getdescriptorinfo"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetDescriptorInfoResult {
    pub descriptor: String,
    pub checksum: String,
    #[serde(rename = "isrange")]
    pub is_range: bool,
    #[serde(rename = "issolvable")]
    pub is_solvable: bool,
    #[serde(rename = "hasprivatekeys")]
    pub has_private_keys: bool,
}

/// Models the request options of "getblocktemplate"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateOptions {
    pub mode: GetBlockTemplateModes,
    //// List of client side supported softfork deployment
    pub rules: Vec<GetBlockTemplateRules>,
    /// List of client side supported features
    pub capabilities: Vec<GetBlockTemplateCapabilities>,
}

/// Enum to represent client-side supported features
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateCapabilities {
    // No features supported yet. In the future this could be, for example, Proposal and Longpolling
}

/// Enum to representing specific block rules that the requested template
/// should support.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateRules {
    SegWit,
    Signet,
    Csv,
    Taproot,
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

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateResultPayeeInfo {
    pub payee: String,
    pub script: String,
    pub amount: usize,
}

/// Models the result of "getblocktemplate"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateResult {
    /// List of features the Bitcoin Core getblocktemplate implementation supports
    pub capabilities: Vec<GetBlockTemplateResultCapabilities>,
    /// Block header version
    pub version: u32,
    /// Block rules that are to be enforced
    pub rules: Vec<GetBlockTemplateResultRules>,
    /// Set of pending, supported versionbit (BIP 9) softfork deployments
    #[serde(rename = "vbavailable")]
    pub version_bits_available: HashMap<u32, String>,
    /// Bit mask of versionbits the server requires set in submissions
    #[serde(rename = "vbrequired")]
    pub version_bits_required: u32,
    /// The previous block hash the current template is mining on
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: BlockHash,
    /// List of transactions included in the template block
    pub transactions: Vec<GetBlockTemplateResultTransaction>,
    /// Data that should be included in the coinbase's scriptSig content. Only
    /// the values (hexadecimal byte-for-byte) in this map should be included,
    /// not the keys. This does not include the block height, which is required
    /// to be included in the scriptSig by BIP 0034. It is advisable to encode
    /// values inside "PUSH" opcodes, so as to not inadvertently expend SIGOPs
    /// (which are counted toward limits, despite not being executed).
    #[serde(rename = "coinbaseaux")]
    pub coinbase_aux: HashMap<String, String>,
    /// Total funds available for the coinbase
    #[serde(rename = "coinbasevalue", with = "dashcore::util::amount::serde::as_sat", default)]
    pub coinbase_value: Amount,
    // TODO figure out what is the data is represented to coinbasetxn
    // pub coinbasetxn:
    /// The number which valid hashes must be less than, in big-endian
    pub target: Vec<u8>,
    /// The minimum timestamp appropriate for the next block time. Expressed as
    /// UNIX timestamp.
    #[serde(rename = "mintime")]
    pub min_time: u64,
    /// List of things that may be changed by the client before submitting a
    /// block
    pub mutable: Vec<GetBlockTemplateResulMutations>,
    // TODO figure out what is the data is represented to value
    // pub value:
    /// A range of valid nonces
    #[serde(rename = "noncerange")]
    pub nonce_range: Vec<u8>,
    /// Block sigops limit
    #[serde(rename = "sigoplimit")]
    pub sigop_limit: u32,
    /// Block size limit
    #[serde(rename = "sizelimit")]
    pub size_limit: u32,
    /// The current time as seen by the server (recommended for block time)
    /// Note: this is not necessarily the system clock, and must fall within
    /// the mintime/maxtime rules. Expressed as UNIX timestamp.
    #[serde(rename = "curtime")]
    pub current_time: u64,
    /// The compressed difficulty in hexadecimal
    #[serde(with = "hex")]
    pub bits: Vec<u8>,
    #[serde(with = "hex", rename = "previousbits")]
    pub previous_bits: Vec<u8>,
    /// The height of the block we will be mining: `current height + 1`
    pub height: u64,
    pub masternode: Vec<GetBlockTemplateResultPayeeInfo>,
    pub masternode_payments_started: bool,
    pub masternode_payments_enforced: bool,
    #[serde(rename = "superblock")]
    pub super_block: Vec<GetBlockTemplateResultPayeeInfo>,
    #[serde(rename = "superblocks_started")]
    pub super_blocks_started: bool,
    #[serde(rename = "superblocks_enabled")]
    pub super_blocks_enabled: bool,
    pub coinbase_payload: String,
}

/// Models a single transaction entry in the result of "getblocktemplate"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateResultTransaction {
    #[serde(with = "hex")]
    pub data: Vec<u8>,
    pub hash: BlockHash,
    /// Transactions that must be in present in the final block if this one is.
    /// Indexed by a 1-based index in the `GetBlockTemplateResult.transactions`
    /// list
    pub depends: Vec<u32>,
    /// The transaction fee
    #[serde(with = "dashcore::util::amount::serde::as_sat")]
    pub fee: Amount,
    /// Transaction sigops
    pub sigops: u32,
}

/// Enum to represent Bitcoin Core's supported features for getblocktemplate
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateResultCapabilities {
    Proposal,
}

/// Enum to representing specific block rules that client must support to work
/// with the template returned by Bitcoin Core
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateResultRules {
    /// Inidcates that the client must support the SegWit rules when using this
    /// template.
    #[serde(alias = "!segwit")]
    SegWit,
    /// Indicates that the client must support the Signet rules when using this
    /// template.
    #[serde(alias = "!signet")]
    Signet,
    /// Indicates that the client must support the CSV rules when using this
    /// template.
    Csv,
    /// Indicates that the client must support the taproot rules when using this
    /// template.
    Taproot,
    /// Indicates that the client must support the Regtest rules when using this
    /// template. TestDummy is a test soft-fork only used on the regtest network.
    Testdummy,
}

/// Enum to representing mutable parts of the block template. This does only
/// cover the muations implemented in Bitcoin Core. More mutations are defined
/// in [BIP-23](https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki#Mutations),
/// but not implemented in the getblocktemplate implementation of Bitcoin Core.
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

/// Models the result of "walletcreatefundedpsbt"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct WalletCreateFundedPsbtResult {
    pub psbt: String,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub fee: Amount,
    #[serde(rename = "changepos")]
    pub change_position: i32,
}

/// Models the result of "walletprocesspsbt"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct WalletProcessPsbtResult {
    pub psbt: String,
    pub complete: bool,
}

/// Models the request for "walletcreatefundedpsbt"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Default)]
pub struct WalletCreateFundedPsbtOptions {
    /// For a transaction with existing inputs, automatically include more if they are not enough (default true).
    /// Added in Bitcoin Core v0.21
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_inputs: Option<bool>,
    #[serde(rename = "changeAddress", skip_serializing_if = "Option::is_none")]
    pub change_address: Option<Address>,
    #[serde(rename = "changePosition", skip_serializing_if = "Option::is_none")]
    pub change_position: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_type: Option<AddressType>,
    #[serde(rename = "includeWatching", skip_serializing_if = "Option::is_none")]
    pub include_watching: Option<bool>,
    #[serde(rename = "lockUnspents", skip_serializing_if = "Option::is_none")]
    pub lock_unspent: Option<bool>,
    #[serde(
        rename = "feeRate",
        skip_serializing_if = "Option::is_none",
        with = "dashcore::util::amount::serde::as_btc::opt"
    )]
    pub fee_rate: Option<Amount>,
    #[serde(rename = "subtractFeeFromOutputs", skip_serializing_if = "Vec::is_empty")]
    pub subtract_fee_from_outputs: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaceable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conf_target: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimate_mode: Option<EstimateMode>,
}

/// Models the result of "finalizepsbt"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct FinalizePsbtResult {
    pub psbt: String,
    pub hex: String,
    pub complete: bool,
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
    pub branch_length: usize,
    /// Status of the tip as seen by Bitcoin Core
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

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum EstimateMode {
    Unset,
    Economical,
    Conservative,
}

/// A wrapper around dashcore::EcdsaSighashType that will be serialized
/// according to what the RPC expects.
pub struct SigHashType(dashcore::EcdsaSighashType);

impl From<dashcore::EcdsaSighashType> for SigHashType {
    fn from(sht: dashcore::EcdsaSighashType) -> SigHashType {
        SigHashType(sht)
    }
}

impl serde::Serialize for SigHashType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self.0 {
            dashcore::EcdsaSighashType::All => "ALL",
            dashcore::EcdsaSighashType::None => "NONE",
            dashcore::EcdsaSighashType::Single => "SINGLE",
            dashcore::EcdsaSighashType::AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
            dashcore::EcdsaSighashType::NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
            dashcore::EcdsaSighashType::SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
        })
    }
}

// Used for createrawtransaction argument.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CreateRawTransactionInput {
    pub txid: dashcore::Txid,
    pub vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionOptions {
    /// For a transaction with existing inputs, automatically include more if they are not enough (default true).
    /// Added in Bitcoin Core v0.21
    #[serde(rename = "add_inputs", skip_serializing_if = "Option::is_none")]
    pub add_inputs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_position: Option<u32>,
    #[serde(rename = "change_type", skip_serializing_if = "Option::is_none")]
    pub change_type: Option<AddressType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_watching: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_unspents: Option<bool>,
    #[serde(
        with = "dashcore::util::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub fee_rate: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtract_fee_from_outputs: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaceable: Option<bool>,
    #[serde(rename = "conf_target", skip_serializing_if = "Option::is_none")]
    pub conf_target: Option<u32>,
    #[serde(rename = "estimate_mode", skip_serializing_if = "Option::is_none")]
    pub estimate_mode: Option<EstimateMode>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionResult {
    pub hex: Vec<u8>,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub fee: Amount,
    #[serde(rename = "changepos")]
    pub change_position: i32,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct GetBalancesResultEntry {
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub trusted: Amount,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub untrusted_pending: Amount,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub immature: Amount,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetBalancesResult {
    pub mine: GetBalancesResultEntry,
    pub watchonly: Option<GetBalancesResultEntry>,
}

impl FundRawTransactionResult {
    pub fn transaction(&self) -> Result<Transaction, encode::Error> {
        encode::deserialize(&self.hex)
    }
}

// Used for signrawtransaction argument.
#[derive(Serialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionInput {
    pub txid: dashcore::Txid,
    pub vout: u32,
    pub script_pub_key: Script,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<Script>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "dashcore::util::amount::serde::as_btc::opt"
    )]
    pub amount: Option<Amount>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetTxOutSetInfoResult {
    /// The current block height (index)
    pub height: u64,
    /// The hash of the block at the tip of the chain
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
    pub hash_serialized_2: sha256::Hash,
    /// The estimated size of the chainstate on disk
    pub disk_size: u64,
    /// The total amount
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
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

/// Used to represent an address type.
#[derive(Copy, Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum AddressType {
    Legacy,
    P2shSegwit,
    Bech32,
}

/// Used to represent arguments that can either be an address or a public key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PubKeyOrAddress<'a> {
    Address(&'a Address),
    PubKey(&'a PublicKey),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
/// Start a scan of the UTXO set for an [output descriptor](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md).
pub enum ScanTxOutRequest {
    /// Scan for a single descriptor
    Single(String),
    /// Scan for a descriptor with xpubs
    Extended {
        /// Descriptor
        desc: String,
        /// Range of the xpub derivations to scan
        range: (u64, u64),
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ScanTxOutResult {
    pub success: Option<bool>,
    #[serde(rename = "txouts")]
    pub tx_outs: Option<u64>,
    pub height: Option<u64>,
    #[serde(rename = "bestblock")]
    pub best_block_hash: Option<BlockHash>,
    pub unspents: Vec<Utxo>,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub total_amount: Amount,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Utxo {
    pub txid: dashcore::Txid,
    pub vout: u32,
    pub script_pub_key: Script,
    #[serde(rename = "desc")]
    pub descriptor: String,
    #[serde(with = "dashcore::util::amount::serde::as_btc")]
    pub amount: Amount,
    pub height: u64,
}

impl<'a> serde::Serialize for PubKeyOrAddress<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            PubKeyOrAddress::Address(a) => serde::Serialize::serialize(a, serializer),
            PubKeyOrAddress::PubKey(k) => serde::Serialize::serialize(k, serializer),
        }
    }
}

// --------------------------- Masternode -------------------------------

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProTxListType {
    Registered,
    Valid,
    Wallet,
}

impl Serialize for ProTxListType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ProTxListType::Registered => serializer.serialize_str("registered"),
            ProTxListType::Valid => serializer.serialize_str("valid"),
            ProTxListType::Wallet => serializer.serialize_str("wallet"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMasternodeCountResult {
    pub total: u32,
    pub enabled: u32,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Masternode {
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
    #[serde_as(as = "DisplayFromStr")]
    pub address: SocketAddr,
    #[serde_as(as = "Bytes")]
    pub payee: Vec<u8>,
    pub status: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(rename = "platformNodeID")]
    pub platform_node_id: Option<String>,
    #[serde(rename = "platformP2PPort")]
    pub platform_p2p_port: Option<u32>,
    #[serde(rename = "platformHTTPPort")]
    pub platform_http_port: Option<u32>,
    #[serde(rename = "pospenaltyscore")]
    pub pos_penalty_score: u32,
    #[serde(rename = "consecutivePayments")]
    pub consecutive_payments: u32,
    #[serde(rename = "lastpaidtime")]
    pub last_paid_time: u32,
    #[serde(rename = "lastpaidblock")]
    pub last_paid_block: u32,
    #[serde_as(as = "Bytes")]
    #[serde(rename = "owneraddress")]
    pub owner_address: Vec<u8>,
    #[serde_as(as = "Bytes")]
    #[serde(rename = "votingaddress")]
    pub voting_address: Vec<u8>,
    #[serde_as(as = "Bytes")]
    #[serde(rename = "collateraladdress")]
    pub collateral_address: Vec<u8>,
    #[serde_as(as = "Bytes")]
    #[serde(rename = "pubkeyoperator")]
    pub pubkey_operator: Vec<u8>,
}

// TODO: clean up the new structure + test deserialization

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum MasternodeType {
    Regular,
    HighPerformance,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MasternodeListItem {
    #[serde(rename = "type")]
    pub node_type: MasternodeType,
    pub protx_hash: ProTxHash,
    // TODO: confirm if this is correct
    pub collateral_hash: [u8; 32],
    pub collateral_index: u32,
    // TODO: add collateral_address
    pub operator_reward: u32,
    pub state: DMNState,
}

pub struct RemovedMasternodeItem {
    pub protx_hash: ProTxHash,
}

pub struct UpdatedMasternodeItem {
    pub protx_hash: ProTxHash,
    pub state_diff: DMNStateDiff,
}

pub struct MasternodeListDiffWithMasternodes {
    pub base_height: u32,
    pub block_height: u32,
    pub added_mns: Vec<MasternodeListItem>,
    pub removed_mns: Vec<RemovedMasternodeItem>,
    pub updated_mns: Vec<UpdatedMasternodeItem>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Payee {
    #[serde_as(as = "Bytes")]
    pub address: Vec<u8>,
    pub script: Script,
    pub amount: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MasternodePayment {
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
    pub amount: u64,
    pub payees: Vec<Payee>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMasternodePaymentsResult {
    pub height: u64,
    #[serde(rename = "blockhash")]
    pub block_hash: BlockHash,
    pub amount: u64,
    pub masternodes: Vec<MasternodePayment>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DMNState {
    #[serde_as(as = "DisplayFromStr")]
    pub service: SocketAddr,
    pub registered_height: u32,
    #[serde(rename = "PoSeRevivedHeight")]
    pub pose_revived_height: u32,
    #[serde(rename = "PoSeBanHeight")]
    pub pose_ban_height: u32,
    pub revocation_reason: u32,
    pub owner_address: [u8; 20],
    pub voting_address: [u8; 20],
    pub payout_address: [u8; 20],
    #[serde_as(as = "Bytes")]
    pub pub_key_operator: Vec<u8>,
    pub operator_payout_address: Option<[u8; 20]>,
    pub platform_node_id: Option<[u8; 20]>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DMNStateDiff {
    pub service: Option<SocketAddr>,
    #[serde(rename = "PoSeRevivedHeight")]
    pub pose_revived_height: Option<u32>,
    #[serde(rename = "PoSeBanHeight")]
    pub pose_ban_height: Option<u32>,
    pub revocation_reason: Option<u32>,
    pub owner_address: Option<[u8; 20]>,
    pub voting_address: Option<[u8; 20]>,
    pub payout_address: Option<[u8; 20]>,
    #[serde_as(as = "Option<Bytes>")]
    pub pub_key_operator: Option<Vec<u8>>,
    pub operator_payout_address: Option<Option<[u8; 20]>>,
    pub platform_node_id: Option<[u8; 20]>,
}

impl DMNState {
    pub fn apply_diff(&mut self, diff: DMNStateDiff) {
        let DMNStateDiff {
            service,
            pose_revived_height,
            pose_ban_height,
            revocation_reason,
            owner_address,
            voting_address,
            payout_address,
            pub_key_operator,
            operator_payout_address,
            platform_node_id,
        } = diff;
        if let Some(service) = service {
            self.service = service
        }
        if let Some(pose_revived_height) = pose_revived_height {
            self.pose_revived_height = pose_revived_height;
        }
        if let Some(pose_ban_height) = pose_ban_height {
            self.pose_ban_height = pose_ban_height;
        }
        if let Some(revocation_reason) = revocation_reason {
            self.revocation_reason = revocation_reason;
        }
        if let Some(owner_address) = owner_address {
            self.owner_address = owner_address;
        }

        if let Some(voting_address) = voting_address {
            self.voting_address = voting_address;
        }
        if let Some(payout_address) = payout_address {
            self.payout_address = payout_address;
        }
        if let Some(pub_key_operator) = pub_key_operator {
            self.pub_key_operator = pub_key_operator;
        }
        if let Some(operator_payout_address) = operator_payout_address {
            self.operator_payout_address = operator_payout_address;
        }
        if let Some(platform_node_id) = platform_node_id {
            self.platform_node_id = Some(platform_node_id);
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum MasternodeState {
    MasternodeWaitingForProtx,
    MasternodePoseBanned,
    MasternodeRemoved,
    MasternodeOperatorKeyChanged,
    MasternodeProtxIpChanged,
    MasternodeReady,
    MasternodeError,
    Unknown,
    Nonrecognised,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MasternodeStatus {
    #[serde(default, deserialize_with = "deserialize_outpoint")]
    pub outpoint: dashcore::OutPoint,
    #[serde_as(as = "DisplayFromStr")]
    pub service: SocketAddr,
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(rename = "collateralHash", with = "hex")]
    pub collateral_hash: Vec<u8>,
    #[serde(rename = "collateralIndex")]
    pub collateral_index: u32,
    #[serde(rename = "dmnState")]
    pub dmn_state: DMNState,
    #[serde(deserialize_with = "deserialize_mn_state")]
    pub state: MasternodeState,
    pub status: String,
}

// --------------------------- BLS -------------------------------

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BLS {
    #[serde_as(as = "Bytes")]
    pub secret: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub public: Vec<u8>,
}

// --------------------------- Quorum -------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize_repr, Hash)]
#[repr(u8)]
pub enum QuorumType {
    Llmq50_60 = 1,
    Llmq400_60 = 2,
    Llmq400_85 = 3,
    Llmq100_67 = 4,
    Llmq60_75 = 5,
    Llmq25_67 = 6,
    LlmqTest = 100,
    LlmqDevnet = 101,
    LlmqTestV17 = 102,
    LlmqTestDip0024 = 103,
    LlmqTestInstantsend = 104,
    LlmqDevnetDip0024 = 105,
    LlmqTestPlatform = 106,
    LlmqDevnetPlatform = 107,
    UNKNOWN = 0,
}

impl From<u32> for QuorumType {
    fn from(value: u32) -> Self {
        match value {
            1 => QuorumType::Llmq50_60,
            2 => QuorumType::Llmq400_60,
            3 => QuorumType::Llmq400_85,
            4 => QuorumType::Llmq100_67,
            5 => QuorumType::Llmq60_75,
            6 => QuorumType::Llmq25_67,
            100 => QuorumType::LlmqTest,
            101 => QuorumType::LlmqDevnet,
            102 => QuorumType::LlmqTestV17,
            103 => QuorumType::LlmqTestDip0024,
            104 => QuorumType::LlmqTestInstantsend,
            105 => QuorumType::LlmqDevnetDip0024,
            106 => QuorumType::LlmqTestPlatform,
            107 => QuorumType::LlmqDevnetPlatform,
            _ => QuorumType::UNKNOWN,
        }
    }
}

impl Display for QuorumType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let value = match self {
            QuorumType::Llmq50_60 => "llmq_50_60",
            QuorumType::Llmq60_75 => "llmq_60_75",
            QuorumType::Llmq400_60 => "llmq_400_60",
            QuorumType::Llmq400_85 => "llmq_400_85",
            QuorumType::Llmq100_67 => "llmq_100_67",
            QuorumType::Llmq25_67 => "llmq_25_67",
            QuorumType::LlmqTest => "llmq_test",
            QuorumType::LlmqTestInstantsend => "llmq_test_instantsend",
            QuorumType::LlmqTestV17 => "llmq_test_v17",
            QuorumType::LlmqTestDip0024 => "llmq_test_dip0024",
            QuorumType::LlmqDevnet => "llmq_devnet",
            QuorumType::LlmqDevnetDip0024 => "llmq_devnet_dip0024",
            QuorumType::UNKNOWN => "unknown",
            QuorumType::LlmqTestPlatform => "llmq_test_platform",
            QuorumType::LlmqDevnetPlatform => "llmq_devnet_platform",
        };
        write!(f, "{}", value)
    }
}

impl From<&str> for QuorumType {
    fn from(value: &str) -> Self {
        match value {
            "llmq_50_60" => QuorumType::Llmq50_60,
            "llmq_60_75" => QuorumType::Llmq60_75,
            "llmq_400_60" => QuorumType::Llmq400_60,
            "llmq_400_85" => QuorumType::Llmq400_85,
            "llmq_100_67" => QuorumType::Llmq100_67,
            "llmq_25_67" => QuorumType::Llmq25_67,
            "llmq_test" => QuorumType::LlmqTest,
            "llmq_test_instantsend" => QuorumType::LlmqTestInstantsend,
            "llmq_test_v17" => QuorumType::LlmqTestV17,
            "llmq_test_dip0024" => QuorumType::LlmqTestDip0024,
            "llmq_devnet" => QuorumType::LlmqDevnet,
            "llmq_devnet_dip0024" => QuorumType::LlmqDevnetDip0024,
            "llmq_test_platform" => QuorumType::LlmqTestPlatform,
            "llmq_devnet_platform" => QuorumType::LlmqDevnetPlatform,
            _ => QuorumType::UNKNOWN,
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtendedQuorumDetails {
    pub creation_height: u32,
    pub quorum_index: Option<u32>,
    pub mined_block_hash: BlockHash,
    pub num_valid_members: u32,
    #[serde(deserialize_with = "deserialize_f32")]
    pub health_ratio: f32,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct QuorumListResult<T> {
    #[serde(flatten)]
    pub quorums_by_type: HashMap<QuorumType, T>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(from = "ExtendedQuorumListResultIntermediate")]
pub struct ExtendedQuorumListResult {
    #[serde(flatten)]
    pub quorums_by_type: HashMap<QuorumType, HashMap<QuorumHash, ExtendedQuorumDetails>>,
}

impl From<ExtendedQuorumListResultIntermediate> for ExtendedQuorumListResult {
    fn from(value: ExtendedQuorumListResultIntermediate) -> Self {
        ExtendedQuorumListResult {
            quorums_by_type: value
                .quorums_by_type
                .into_iter()
                .map(|(quorum_type, vec)| {
                    (
                        quorum_type,
                        vec.into_iter()
                            .flatten()
                            .collect::<HashMap<QuorumHash, ExtendedQuorumDetails>>(),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct ExtendedQuorumListResultIntermediate {
    #[serde(flatten)]
    pub quorums_by_type: HashMap<QuorumType, Vec<HashMap<QuorumHash, ExtendedQuorumDetails>>>,
}

impl<'de> Deserialize<'de> for QuorumType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(QuorumType::from(s.as_str()))
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct QuorumListResultInternal<T> {
    pub llmq_50_60: Option<Vec<T>>,
    pub llmq_400_60: Option<Vec<T>>,
    pub llmq_400_85: Option<Vec<T>>,
    pub llmq_100_67: Option<Vec<T>>,
    pub llmq_60_75: Option<Vec<T>>,
    pub llmq_25_67: Option<Vec<T>>,
    // for devnets only
    pub llmq_devnet: Option<Vec<T>>,
    pub llmq_devnet_platform: Option<Vec<T>>,
    // for devnets only. rotated version (v2) for devnets
    pub llmq_devnet_dip0024: Option<Vec<T>>,
    // for testing only
    pub llmq_test: Option<Vec<T>>,
    pub llmq_test_instantsend: Option<Vec<T>>,
    pub llmq_test_v17: Option<Vec<T>>,
    pub llmq_test_dip0024: Option<Vec<T>>,
    pub llmq_test_platform: Option<Vec<T>>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumMember {
    pub pro_tx_hash: ProTxHash,
    #[serde_as(as = "Bytes")]
    pub pub_key_operator: Vec<u8>,
    pub valid: bool,
    #[serde(deserialize_with = "deserialize_hex_opt")]
    pub pub_key_share: Option<Vec<u8>>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumInfoResult {
    pub height: u32,
    #[serde(rename = "type", deserialize_with = "deserialize_quorum_type")]
    pub quorum_type: QuorumType,
    pub quorum_hash: QuorumHash,
    pub quorum_index: u32,
    #[serde(with = "hex")]
    pub mined_block: Vec<u8>,
    pub members: Vec<QuorumMember>,
    #[serde_as(as = "Bytes")]
    pub quorum_public_key: Vec<u8>,
    #[serde(default, deserialize_with = "deserialize_hex_opt")]
    pub secret_key_share: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumSessionStatusMember {
    pub member_index: u32,
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MemberDetail {
    Level0(i32),
    Level1(Vec<i32>),
    Level2(Vec<QuorumSessionStatusMember>),
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumSessionStatus {
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_hash: QuorumHash,
    pub quorum_height: u32,
    pub phase: u8,
    pub sent_contributions: bool,
    pub sent_complaint: bool,
    pub sent_justification: bool,
    pub sent_premature_commitment: bool,
    pub aborted: bool,
    pub bad_members: MemberDetail,
    pub we_complain: MemberDetail,
    pub received_contributions: MemberDetail,
    pub received_complaints: MemberDetail,
    pub received_justifications: MemberDetail,
    pub received_premature_commitments: MemberDetail,
    pub all_members: Option<Vec<QuorumHash>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumSession {
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_index: u32,
    pub status: QuorumSessionStatus,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumConnectionInfo {
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<SocketAddr>,
    pub outbound: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumConnection {
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_index: u32,
    pub p_quorum_base_block_index: Option<u32>,
    pub quorum_hash: Option<QuorumHash>,
    pub pindex_tip: Option<u32>,
    pub quorum_connections: Option<Vec<QuorumConnectionInfo>>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumMinableCommitments {
    pub version: u8,
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_hash: QuorumHash,
    pub quorum_index: u32,
    pub signers_count: u32,
    #[serde_as(as = "Bytes")]
    pub signers: Vec<u8>,
    pub valid_members_count: u32,
    #[serde_as(as = "Bytes")]
    pub valid_members: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub quorum_public_key: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub quorum_vvec_hash: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub quorum_sig: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub members_sig: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumItemDeleted {
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_hash: QuorumHash,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumDKGStatus {
    pub time: u64,
    pub time_str: String,
    pub session: Vec<QuorumSession>,
    pub quorum_connections: Vec<QuorumConnection>,
    pub minable_commitments: Vec<QuorumMinableCommitments>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumSignature {
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_hash: QuorumHash,
    pub quorum_member: Option<u8>,
    #[serde(with = "hex")]
    pub id: Vec<u8>,
    #[serde(with = "hex")]
    pub msg_hash: Vec<u8>,
    #[serde(with = "hex")]
    pub sign_hash: Vec<u8>,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum QuorumSignResult {
    QuorumSignStatus(bool),
    QuorumSignSignatureShare(QuorumSignature),
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumMemberOf {
    pub height: u32,
    #[serde(rename = "type", deserialize_with = "deserialize_quorum_type")]
    pub quorum_type: QuorumType,
    pub quorum_hash: QuorumHash,
    #[serde(with = "hex")]
    pub mined_block: Vec<u8>,
    #[serde(with = "hex")]
    pub quorum_public_key: Vec<u8>,
    pub is_valid_member: bool,
    pub member_index: u32,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct QuorumMemberOfResult(pub Vec<QuorumMemberOf>);

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumSnapshot {
    pub active_quorum_members: Vec<bool>,
    pub mn_skip_list_mode: u8,
    pub mn_skip_list: Vec<u8>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumMasternodeListItem {
    pub pro_reg_tx_hash: Vec<u8>,
    pub confirmed_hash: Vec<u8>,
    #[serde_as(as = "DisplayFromStr")]
    pub service: SocketAddr,
    #[serde_as(as = "Bytes")]
    pub pub_key_operator: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub voting_address: Vec<u8>,
    pub is_valid: bool,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MasternodeListDiff {
    pub base_block_hash: dashcore::BlockHash,
    pub block_hash: dashcore::BlockHash,
    #[serde_as(as = "Bytes")]
    pub cb_tx_merkle_tree: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub cb_tx: Vec<u8>,
    #[serde(rename = "deletedMNs")]
    pub deleted_mns: Vec<QuorumMasternodeListItem>,
    pub mn_list: Vec<QuorumMasternodeListItem>,
    pub deleted_quorums: Vec<QuorumItemDeleted>,
    pub new_quorums: Vec<QuorumMinableCommitments>,
    #[serde(rename = "merkleRootMNList", with = "hex")]
    pub merkle_root_mn_list: Vec<u8>,
    #[serde(rename = "merkleRootQuorums", with = "hex")]
    pub merkle_root_quorums: Vec<u8>,
}

// #[serde_as]
// #[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
// #[serde(rename_all = "camelCase")]
// pub struct MasternodeListDiffWithMasternodes {
//     pub base_block_hash: dashcore::BlockHash,
//     pub block_hash: dashcore::BlockHash,
//     #[serde_as(as = "Bytes")]
//     pub cb_tx_merkle_tree: Vec<u8>,
//     #[serde_as(as = "Bytes")]
//     pub cb_tx: Vec<u8>,
//     #[serde(rename = "deletedMNs")]
//     pub deleted_mns: Vec<Masternode>,
//     pub mn_list: Vec<Masternode>,
//     pub deleted_quorums: Vec<QuorumItemDeleted>,
//     pub new_quorums: Vec<QuorumMinableCommitments>,
//     #[serde(rename = "merkleRootMNList", with = "hex")]
//     pub merkle_root_mn_list: Vec<u8>,
//     #[serde(rename = "merkleRootQuorums", with = "hex")]
//     pub merkle_root_quorums: Vec<u8>,
// }

// #[serde_as]
// #[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
// pub struct {
//
// }

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumRotationInfo {
    pub extra_share: bool,
    pub quorum_snapshot_at_h_minus_c: QuorumSnapshot,
    pub quorum_snapshot_at_h_minus_2c: QuorumSnapshot,
    pub quorum_snapshot_at_h_minus_3c: QuorumSnapshot,
    pub mn_list_diff_tip: MasternodeListDiff,
    pub mn_list_diff_h: MasternodeListDiff,
    pub mn_list_diff_at_h_minus_c: MasternodeListDiff,
    pub mn_list_diff_at_h_minus_2c: MasternodeListDiff,
    pub mn_list_diff_at_h_minus_3c: MasternodeListDiff,
    pub block_hash_list: Vec<dashcore::BlockHash>,
    pub quorum_snapshot_list: Vec<QuorumSnapshot>,
    pub mn_list_diff_list: Vec<MasternodeListDiff>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectQuorumResult {
    pub quorum_hash: QuorumHash,
    pub recovery_members: Vec<QuorumHash>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum IntegerOrString<'a> {
    Integer(u32),
    String(&'a str),
}

// --------------------------- ProTx -------------------------------

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Wallet {
    pub has_owner_key: bool,
    pub has_operator_key: bool,
    pub has_voting_key: bool,
    pub owns_collateral: bool,
    pub owns_payee_script: bool,
    pub owns_operator_reward_script: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaInfo {
    #[serde(rename = "lastDSQ")]
    pub last_dsq: u32,
    pub mixing_tx_count: u32,
    pub last_outbound_attempt: i32,
    pub last_outbound_attempt_elapsed: i32,
    pub last_outbound_success: i32,
    pub last_outbound_success_elapsed: i32,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProTxInfo {
    #[serde(rename = "type")]
    mn_type: Option<String>,
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
    #[serde(with = "hex")]
    pub collateral_hash: Vec<u8>,
    pub collateral_index: u32,
    #[serde_as(as = "Bytes")]
    pub collateral_address: Vec<u8>,
    pub operator_reward: u32,
    pub state: DMNState,
    pub confirmations: u32,
    #[serde(default)]
    pub wallet: Option<Wallet>,
    pub meta_info: MetaInfo,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProTxList {
    Hex(Vec<ProTxHash>),
    Info(Vec<ProTxInfo>),
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProTxRegPrepare {
    pub tx: ProTxHash,
    #[serde_as(as = "Bytes")]
    pub collateral_address: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub sign_message: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProTxRevokeReason {
    NotSpecified = 0,
    TerminationOfService = 1,
    CompromisedKeys = 2,
    ChangeOfKeys = 3,
    NotRecognised = 4,
}

// Custom deserializer functions.

/// deserialize_hex_opt deserializes a vector of hex-encoded byte array.
fn deserialize_hex_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Vec<u8> = hex::decode(String::deserialize(deserializer)?).unwrap();
    Ok(Some(v))
}

/// deserialize_outpoint deserializes a hex-encoded outpoint
fn deserialize_outpoint<'de, D>(deserializer: D) -> Result<dashcore::OutPoint, D::Error>
where
    D: Deserializer<'de>,
{
    let str_sequence = String::deserialize(deserializer)?;
    let str_array: Vec<String> = str_sequence.split('-').map(|item| item.to_owned()).collect();

    let txid: dashcore::Txid = dashcore::Txid::from_hex(&str_array[0]).unwrap();
    let vout: u32 = str_array[1].parse().unwrap();

    let outpoint = dashcore::OutPoint {
        txid: txid,
        vout: vout,
    };
    Ok(outpoint)
}

/// deserialize_mn_state deserializes a masternode state
fn deserialize_mn_state<'de, D>(deserializer: D) -> Result<MasternodeState, D::Error>
where
    D: Deserializer<'de>,
{
    let str_sequence = String::deserialize(deserializer)?;

    Ok(match str_sequence.as_str() {
        "WAITING_FOR_PROTX" => MasternodeState::MasternodeWaitingForProtx,
        "POSE_BANNED" => MasternodeState::MasternodePoseBanned,
        "REMOVED" => MasternodeState::MasternodeRemoved,
        "OPERATOR_KEY_CHANGED" => MasternodeState::MasternodeOperatorKeyChanged,
        "PROTX_IP_CHANGED" => MasternodeState::MasternodeProtxIpChanged,
        "READY" => MasternodeState::MasternodeReady,
        "ERROR" => MasternodeState::MasternodeError,
        "UNKNOWN" => MasternodeState::Unknown,
        _ => MasternodeState::Nonrecognised,
    })
}

/// deserialize_quorum_type deserializes a quorum type
fn deserialize_quorum_type<'de, D>(deserializer: D) -> Result<QuorumType, D::Error>
where
    D: Deserializer<'de>,
{
    return match IntegerOrString::deserialize(deserializer)? {
        IntegerOrString::String(s) => {
            let qt: QuorumType = s.into();
            Ok(qt)
        }
        IntegerOrString::Integer(n) => {
            let qt: QuorumType = n.into();
            Ok(qt)
        }
    };
}

fn deserialize_f32<'de, D>(deserializer: D) -> Result<f32, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::String(s) => s.parse().map_err(de::Error::custom)?,
        Value::Number(num) => num.as_f64().ok_or(de::Error::custom("Invalid number"))? as f32,
        _ => return Err(de::Error::custom("wrong type")),
    })
}

#[cfg(test)]
mod tests {
    use crate::{ExtendedQuorumDetails, ExtendedQuorumListResult, QuorumListResult};

    #[test]
    fn deserialize_quorum_listextended() {
        let json_list = r#"{
              "llmq_50_60": [
                {
                  "000000da4509523408c751905d4e48df335e3ee565b4d2288800c7e51d592e2f": {
                    "creationHeight": 871992,
                    "minedBlockHash": "000000cd7f101437069956c0ca9f4180b41f0506827a828d57e85b35f215487e",
                    "numValidMembers": 50,
                    "healthRatio": "1.00"
                  }
                }
              ]
            }"#;
        let result: ExtendedQuorumListResult =
            serde_json::from_str(json_list).expect("expected to deserialize json");
        println!("{:#?}", result);
    }
}
