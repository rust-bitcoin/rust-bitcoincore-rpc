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

#![crate_name = "bitcoincore_rpc_json"]
#![crate_type = "rlib"]
#![allow(deprecated)]           // Because of `GetPeerInfoResultNetwork::Unroutable`.

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
use bitcoin::{Address, Amount, PrivateKey, PublicKey, SignedAmount, Transaction, ScriptBuf, Script, bip158, bip32, Network};
use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};
use std::fmt;

//TODO(stevenroose) consider using a Time type

/// A module used for serde serialization of bytes in hexadecimal format.
///
/// The module is compatible with the serde attribute.
pub mod serde_hex {
    use bitcoin::hex::{DisplayHex, FromHex};
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b.to_lower_hex_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let hex_str: String = ::serde::Deserialize::deserialize(d)?;
        Ok(FromHex::from_hex(&hex_str).map_err(D::Error::custom)?)
    }

    pub mod opt {
        use bitcoin::hex::{DisplayHex, FromHex};
        use serde::de::Error;
        use serde::{Deserializer, Serializer};

        pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match *b {
                None => s.serialize_none(),
                Some(ref b) => s.serialize_str(&b.to_lower_hex_string()),
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

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetworkInfoResultAddress {
    pub address: String,
    pub port: usize,
    pub score: usize,
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
    pub connections: usize,
    /// The number of inbound connections
    /// Added in Bitcoin Core v0.21
    pub connections_in: Option<usize>,
    /// The number of outbound connections
    /// Added in Bitcoin Core v0.21
    pub connections_out: Option<usize>,
    #[serde(rename = "networkactive")]
    pub network_active: bool,
    pub networks: Vec<GetNetworkInfoResultNetwork>,
    #[serde(rename = "relayfee", with = "bitcoin::amount::serde::as_btc")]
    pub relay_fee: Amount,
    #[serde(rename = "incrementalfee", with = "bitcoin::amount::serde::as_btc")]
    pub incremental_fee: Amount,
    #[serde(rename = "localaddresses")]
    pub local_addresses: Vec<GetNetworkInfoResultAddress>,
    pub warnings: StringOrStringArray,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMultiSigAddressResult {
    pub address: Address<NetworkUnchecked>,
    pub redeem_script: ScriptBuf,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct LoadWalletResult {
    pub name: String,
    pub warning: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct UnloadWalletResult {
    pub warning: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ListWalletDirResult {
    pub wallets: Vec<ListWalletDirItem>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ListWalletDirItem {
    pub name: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetWalletInfoResult {
    #[serde(rename = "walletname")]
    pub wallet_name: String,
    #[serde(rename = "walletversion")]
    pub wallet_version: u32,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub balance: Amount,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub unconfirmed_balance: Amount,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub immature_balance: Amount,
    #[serde(rename = "txcount")]
    pub tx_count: usize,
    #[serde(rename = "keypoololdest")]
    pub keypool_oldest: Option<usize>,
    #[serde(rename = "keypoolsize")]
    pub keypool_size: usize,
    #[serde(rename = "keypoolsize_hd_internal")]
    pub keypool_size_hd_internal: usize,
    pub unlocked_until: Option<u64>,
    #[serde(rename = "paytxfee", with = "bitcoin::amount::serde::as_btc")]
    pub pay_tx_fee: Amount,
    #[serde(rename = "hdseedid")]
    pub hd_seed_id: Option<bitcoin::bip32::XKeyIdentifier>,
    pub private_keys_enabled: bool,
    pub avoid_reuse: Option<bool>,
    pub scanning: Option<ScanningDetails>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(untagged)]
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
#[serde(rename_all = "camelCase")]
pub struct GetBlockResult {
    pub hash: bitcoin::BlockHash,
    pub confirmations: i32,
    pub size: usize,
    pub strippedsize: Option<usize>,
    pub weight: usize,
    pub height: usize,
    pub version: i32,
    #[serde(default, with = "crate::serde_hex::opt")]
    pub version_hex: Option<Vec<u8>>,
    pub merkleroot: bitcoin::hash_types::TxMerkleNode,
    pub tx: Vec<bitcoin::Txid>,
    pub time: usize,
    pub mediantime: Option<usize>,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    #[serde(with = "crate::serde_hex")]
    pub chainwork: Vec<u8>,
    pub n_tx: usize,
    pub previousblockhash: Option<bitcoin::BlockHash>,
    pub nextblockhash: Option<bitcoin::BlockHash>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResult {
    pub hash: bitcoin::BlockHash,
    pub confirmations: i32,
    pub height: usize,
    pub version: Version,
    #[serde(default, with = "crate::serde_hex::opt")]
    pub version_hex: Option<Vec<u8>>,
    #[serde(rename = "merkleroot")]
    pub merkle_root: bitcoin::hash_types::TxMerkleNode,
    pub time: usize,
    #[serde(rename = "mediantime")]
    pub median_time: Option<usize>,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    #[serde(with = "crate::serde_hex")]
    pub chainwork: Vec<u8>,
    pub n_tx: usize,
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: Option<bitcoin::BlockHash>,
    #[serde(rename = "nextblockhash")]
    pub next_block_hash: Option<bitcoin::BlockHash>,
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
    pub fee_rate_percentiles: FeeRatePercentiles,
    pub height: u64,
    pub ins: usize,
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
    #[serde(rename = "swtotal_size")]
    pub sw_total_size: usize,
    #[serde(rename = "swtotal_weight")]
    pub sw_total_weight: usize,
    #[serde(rename = "swtxs")]
    pub sw_txs: usize,
    pub time: u64,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub total_out: Amount,
    pub total_size: usize,
    pub total_weight: usize,
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
    #[serde(default, rename = "feerate_percentiles", skip_serializing_if = "Option::is_none")]
    pub fee_rate_percentiles: Option<FeeRatePercentiles>,
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
    #[serde(default, rename = "swtotal_size", skip_serializing_if = "Option::is_none")]
    pub sw_total_size: Option<usize>,
    #[serde(default, rename = "swtotal_weight", skip_serializing_if = "Option::is_none")]
    pub sw_total_weight: Option<usize>,
    #[serde(default, rename = "swtxs", skip_serializing_if = "Option::is_none")]
    pub sw_txs: Option<usize>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_weight: Option<usize>,
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

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct FeeRatePercentiles {
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub fr_10th: Amount,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub fr_25th: Amount,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub fr_50th: Amount,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub fr_75th: Amount,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
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
    #[serde(deserialize_with = "deserialize_bip70_network")]
    pub chain: Network,
    pub warnings: StringOrStringArray,
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
    /// Not provided for coinbase txs.
    #[serde(default, deserialize_with = "deserialize_hex_array_opt")]
    pub txinwitness: Option<Vec<Vec<u8>>>,
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
    pub req_sigs: Option<usize>,
    #[serde(rename = "type")]
    pub type_: Option<ScriptPubkeyType>,
    // Deprecated in Bitcoin Core 22
    #[serde(default)]
    pub addresses: Vec<Address<NetworkUnchecked>>,
    // Added in Bitcoin Core 22
    #[serde(default)]
    pub address: Option<Address<NetworkUnchecked>>,
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
    #[serde(rename = "in_active_chain")]
    pub in_active_chain: Option<bool>,
    #[serde(with = "crate::serde_hex")]
    pub hex: Vec<u8>,
    pub txid: bitcoin::Txid,
    pub hash: bitcoin::Wtxid,
    pub size: usize,
    pub vsize: usize,
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<GetRawTransactionResultVin>,
    pub vout: Vec<GetRawTransactionResultVout>,
    pub blockhash: Option<bitcoin::BlockHash>,
    pub confirmations: Option<u32>,
    pub time: Option<usize>,
    pub blocktime: Option<usize>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockFilterResult {
    pub header: bitcoin::hash_types::FilterHash,
    #[serde(with = "crate::serde_hex")]
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

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetTransactionResultDetail {
    pub address: Option<Address<NetworkUnchecked>>,
    pub category: GetTransactionResultDetailCategory,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub amount: SignedAmount,
    pub label: Option<String>,
    pub vout: u32,
    #[serde(default, with = "bitcoin::amount::serde::as_btc::opt")]
    pub fee: Option<SignedAmount>,
    pub abandoned: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct WalletTxInfo {
    pub confirmations: i32,
    pub blockhash: Option<bitcoin::BlockHash>,
    pub blockindex: Option<usize>,
    pub blocktime: Option<u64>,
    pub blockheight: Option<u32>,
    pub txid: bitcoin::Txid,
    pub time: u64,
    pub timereceived: u64,
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: Bip125Replaceable,
    /// Conflicting transaction ids
    #[serde(rename = "walletconflicts")]
    pub wallet_conflicts: Vec<bitcoin::Txid>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetTransactionResult {
    #[serde(flatten)]
    pub info: WalletTxInfo,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub amount: SignedAmount,
    #[serde(default, with = "bitcoin::amount::serde::as_btc::opt")]
    pub fee: Option<SignedAmount>,
    pub details: Vec<GetTransactionResultDetail>,
    #[serde(with = "crate::serde_hex")]
    pub hex: Vec<u8>,
}

impl GetTransactionResult {
    pub fn transaction(&self) -> Result<Transaction, encode::Error> {
        Ok(encode::deserialize(&self.hex)?)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ListTransactionResult {
    #[serde(flatten)]
    pub info: WalletTxInfo,
    #[serde(flatten)]
    pub detail: GetTransactionResultDetail,

    pub trusted: Option<bool>,
    pub comment: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ListSinceBlockResult {
    pub transactions: Vec<ListTransactionResult>,
    #[serde(default)]
    pub removed: Vec<ListTransactionResult>,
    pub lastblock: bitcoin::BlockHash,
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

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentQueryOptions {
    #[serde(
        rename = "minimumAmount",
        with = "bitcoin::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_amount: Option<Amount>,
    #[serde(
        rename = "maximumAmount",
        with = "bitcoin::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub maximum_amount: Option<Amount>,
    #[serde(rename = "maximumCount", skip_serializing_if = "Option::is_none")]
    pub maximum_count: Option<usize>,
    #[serde(
        rename = "minimumSumAmount",
        with = "bitcoin::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_sum_amount: Option<Amount>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentResultEntry {
    pub txid: bitcoin::Txid,
    pub vout: u32,
    pub address: Option<Address<NetworkUnchecked>>,
    pub label: Option<String>,
    pub redeem_script: Option<ScriptBuf>,
    pub witness_script: Option<ScriptBuf>,
    pub script_pub_key: ScriptBuf,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub amount: Amount,
    pub confirmations: u32,
    pub spendable: bool,
    pub solvable: bool,
    #[serde(rename = "desc")]
    pub descriptor: Option<String>,
    pub safe: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListReceivedByAddressResult {
    #[serde(default, rename = "involvesWatchonly")]
    pub involved_watch_only: bool,
    pub address: Address<NetworkUnchecked>,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub amount: Amount,
    pub confirmations: u32,
    pub label: String,
    pub txids: Vec<bitcoin::Txid>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionResultError {
    pub txid: bitcoin::Txid,
    pub vout: u32,
    pub script_sig: ScriptBuf,
    pub sequence: u32,
    pub error: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionResult {
    #[serde(with = "crate::serde_hex")]
    pub hex: Vec<u8>,
    pub complete: bool,
    pub errors: Option<Vec<SignRawTransactionResultError>>,
}

impl SignRawTransactionResult {
    pub fn transaction(&self) -> Result<Transaction, encode::Error> {
        Ok(encode::deserialize(&self.hex)?)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TestMempoolAcceptResult {
    pub txid: bitcoin::Txid,
    pub allowed: bool,
    #[serde(rename = "reject-reason")]
    pub reject_reason: Option<String>,
    /// Virtual transaction size as defined in BIP 141 (only present when 'allowed' is true)
    /// Added in Bitcoin Core v0.21
    pub vsize: Option<u64>,
    /// Transaction fees (only present if 'allowed' is true)
    /// Added in Bitcoin Core v0.21
    pub fees: Option<TestMempoolAcceptResultFees>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Fees {
    /// Transaction fee.
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub base: Amount,

    /// If the transaction was not already in the mempool, the effective feerate
    /// in BTC per KvB. For example, the package feerate and/or feerate with
    /// modified fees from prioritisetransaction.
    #[serde(default, rename = "effective-feerate", with = "bitcoin::amount::serde::as_btc::opt")]
    pub effective_feerate: Option<Amount>,

    /// If effective-feerate is provided, the wtxids of the transactions whose
    /// fees and vsizes are included in effective-feerate.
    #[serde(rename = "effective-includes")]
    pub effective_includes: Option<Vec<bitcoin::Wtxid>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TxResult {
    pub txid: bitcoin::Txid,

    /// The wtxid of a different transaction with the same txid but different
    /// witness found in the mempool. This means the submitted transaction was
    /// ignored.
    #[serde(rename = "other-wtxid")]
    pub other_wtxid: Option<bitcoin::Wtxid>,

    /// Virtual transaction size as defined in BIP 141.
    pub vsize: u64,

    pub fees: Fees,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct SubmitPackageResult {
    /// Transaction results keyed by wtxid.
    #[serde(rename = "tx-results")]
    pub tx_results: HashMap<bitcoin::Wtxid, TxResult>,

    /// List of txids of replaced transactions.
    #[serde(rename = "replaced-transactions")]
    pub replaced_transactions: Vec<bitcoin::Txid>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TestMempoolAcceptResultFees {
    /// Transaction fee in BTC
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub base: Amount,
    // unlike GetMempoolEntryResultFees, this only has the `base` fee
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
    pub period: u32,
    pub threshold: Option<u32>,
    pub elapsed: u32,
    pub count: u32,
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
    #[serde(other)]
    Other,
}

/// Status of a softfork
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Softfork {
    #[serde(rename = "type")]
    pub type_: SoftforkType,
    pub bip9: Option<Bip9SoftforkInfo>,
    pub height: Option<u32>,
    pub active: bool,
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
pub struct GetAddressInfoResultEmbedded {
    pub address: Address<NetworkUnchecked>,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptBuf,
    #[serde(rename = "is_script")]
    pub is_script: Option<bool>,
    #[serde(rename = "is_witness")]
    pub is_witness: Option<bool>,
    pub witness_version: Option<u32>,
    #[serde(with = "crate::serde_hex")]
    pub witness_program: Vec<u8>,
    pub script: Option<ScriptPubkeyType>,
    /// The redeemscript for the p2sh address.
    #[serde(default, with = "crate::serde_hex::opt")]
    pub hex: Option<Vec<u8>>,
    pub pubkeys: Option<Vec<PublicKey>>,
    #[serde(rename = "sigsrequired")]
    pub n_signatures_required: Option<usize>,
    pub pubkey: Option<PublicKey>,
    #[serde(rename = "is_compressed")]
    pub is_compressed: Option<bool>,
    pub label: Option<String>,
    #[serde(rename = "hdkeypath")]
    pub hd_key_path: Option<bip32::DerivationPath>,
    #[serde(rename = "hdseedid")]
    pub hd_seed_id: Option<bitcoin::bip32::XKeyIdentifier>,
    #[serde(default)]
    pub labels: Vec<GetAddressInfoResultLabel>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
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
    pub address: Address<NetworkUnchecked>,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptBuf,
    #[serde(rename = "ismine")]
    pub is_mine: Option<bool>,
    #[serde(rename = "iswatchonly")]
    pub is_watchonly: Option<bool>,
    #[serde(rename = "isscript")]
    pub is_script: Option<bool>,
    #[serde(rename = "iswitness")]
    pub is_witness: Option<bool>,
    pub witness_version: Option<u32>,
    #[serde(default, with = "crate::serde_hex::opt")]
    pub witness_program: Option<Vec<u8>>,
    pub script: Option<ScriptPubkeyType>,
    /// The redeemscript for the p2sh address.
    #[serde(default, with = "crate::serde_hex::opt")]
    pub hex: Option<Vec<u8>>,
    pub pubkeys: Option<Vec<PublicKey>>,
    #[serde(rename = "sigsrequired")]
    pub n_signatures_required: Option<usize>,
    pub pubkey: Option<PublicKey>,
    /// Information about the address embedded in P2SH or P2WSH, if relevant and known.
    pub embedded: Option<GetAddressInfoResultEmbedded>,
    #[serde(rename = "is_compressed")]
    pub is_compressed: Option<bool>,
    pub timestamp: Option<u64>,
    #[serde(rename = "hdkeypath")]
    pub hd_key_path: Option<bip32::DerivationPath>,
    #[serde(rename = "hdseedid")]
    pub hd_seed_id: Option<bitcoin::bip32::XKeyIdentifier>,
    pub labels: Vec<GetAddressInfoResultLabel>,
    /// Deprecated in v0.20.0. See `labels` field instead.
    #[deprecated(note = "since Core v0.20.0")]
    pub label: Option<String>,
}

/// Used to represent values that can either be a string or a string array.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum StringOrStringArray {
	String(String),
	StringArray(Vec<String>),
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
    /// Estimate of whether this node is in Initial Block Download mode
    #[serde(rename = "initialblockdownload")]
    pub initial_block_download: bool,
    /// Total amount of work in active chain, in hexadecimal
    #[serde(rename = "chainwork", with = "crate::serde_hex")]
    pub chain_work: Vec<u8>,
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
    pub softforks: HashMap<String, Softfork>,
    /// Any network and blockchain warnings. In later versions of bitcoind, it's an array of strings.
    pub warnings: StringOrStringArray,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ImportMultiRequestScriptPubkey<'a> {
    Address(&'a Address),
    Script(&'a Script),
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolInfoResult {
    /// True if the mempool is fully loaded
    pub loaded: Option<bool>,
    /// Current tx count
    pub size: usize,
    /// Sum of all virtual transaction sizes as defined in BIP 141. Differs from actual serialized size because witness data is discounted
    pub bytes: usize,
    /// Total memory usage for the mempool
    pub usage: usize,
    /// Total fees for the mempool in BTC, ignoring modified fees through prioritisetransaction
    #[serde(default, with = "bitcoin::amount::serde::as_btc::opt")]
    pub total_fee: Option<Amount>,
    /// Maximum memory usage for the mempool
    #[serde(rename = "maxmempool")]
    pub max_mempool: usize,
    /// Minimum fee rate in BTC/kvB for tx to be accepted. Is the maximum of minrelaytxfee and minimum mempool fee
    #[serde(rename = "mempoolminfee", with = "bitcoin::amount::serde::as_btc")]
    pub mempool_min_fee: Amount,
    /// Current minimum relay fee for transactions
    #[serde(rename = "minrelaytxfee", with = "bitcoin::amount::serde::as_btc")]
    pub min_relay_tx_fee: Amount,
    /// Minimum fee rate increment for mempool limiting or replacement in BTC/kvB
    #[serde(rename = "incrementalrelayfee", default, with = "bitcoin::amount::serde::as_btc::opt")]
    pub incremental_relay_fee: Option<Amount>,
    /// Current number of transactions that haven't passed initial broadcast yet
    #[serde(rename = "unbroadcastcount")]
    pub unbroadcast_count: Option<usize>,
    /// True if the mempool accepts RBF without replaceability signaling inspection
    #[serde(rename = "fullrbf")]
    pub full_rbf: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolEntryResult {
    /// Virtual transaction size as defined in BIP 141. This is different from actual serialized
    /// size for witness transactions as witness data is discounted.
    #[serde(alias = "size")]
    pub vsize: u64,
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
    pub wtxid: bitcoin::Txid,
    /// Fee information
    pub fees: GetMempoolEntryResultFees,
    /// Unconfirmed transactions used as inputs for this transaction
    pub depends: Vec<bitcoin::Txid>,
    /// Unconfirmed transactions spending outputs from this transaction
    #[serde(rename = "spentby")]
    pub spent_by: Vec<bitcoin::Txid>,
    /// Whether this transaction could be replaced due to BIP125 (replace-by-fee)
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: bool,
    /// Whether this transaction is currently unbroadcast (initial broadcast not yet acknowledged by any peers)
    /// Added in Bitcoin Core v0.21
    pub unbroadcast: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolEntryResultFees {
    /// Transaction fee in BTC
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub base: Amount,
    /// Transaction fee with fee deltas used for mining priority in BTC
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub modified: Amount,
    /// Modified fees (see above) of in-mempool ancestors (including this one) in BTC
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub ancestor: Amount,
    /// Modified fees (see above) of in-mempool descendants (including this one) in BTC
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub descendant: Amount,
}

impl<'a> serde::Serialize for ImportMultiRequestScriptPubkey<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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
                serializer.serialize_str(&script.to_hex_string())
            }
        }
    }
}

/// A import request for importmulti.
///
/// Note: unlike in bitcoind, `timestamp` defaults to 0.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize)]
pub struct ImportMultiRequest<'a> {
    pub timestamp: Timestamp,
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
pub enum Timestamp {
    Now,
    Time(u64),
}

impl serde::Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match *self {
            Timestamp::Now => serializer.serialize_str("now"),
            Timestamp::Time(timestamp) => serializer.serialize_u64(timestamp),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Timestamp;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "unix timestamp or 'now'")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Timestamp::Time(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value == "now" {
                    Ok(Timestamp::Now)
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

impl Default for Timestamp {
    fn default() -> Self {
        Timestamp::Time(0)
    }
}

impl From<u64> for Timestamp {
    fn from(t: u64) -> Self {
        Timestamp::Time(t)
    }
}

impl From<Option<u64>> for Timestamp {
    fn from(timestamp: Option<u64>) -> Self {
        timestamp.map_or(Timestamp::Now, Timestamp::Time)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ImportMultiResultError {
    pub code: i64,
    pub message: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ImportMultiResult {
    pub success: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub error: Option<ImportMultiResultError>,
}

/// A import request for importdescriptors.
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct ImportDescriptors {
    #[serde(rename = "desc")]
    pub descriptor: String,
    pub timestamp: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<(usize, usize)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
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
    // TODO: use a type for addr
    pub addr: String,
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
    #[serde(rename = "minfeefilter", default, with = "bitcoin::amount::serde::as_btc::opt")]
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
    #[deprecated]
    Unroutable,
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
        with = "bitcoin::amount::serde::as_btc::opt"
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
    pub hash: bitcoin::BlockHash,
    pub height: u64,
}

/// Models the result of "getdescriptorinfo"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetDescriptorInfoResult {
    pub descriptor: String,
    pub checksum: Option<String>,
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

/// Models the result of "getblocktemplate"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateResult {
    /// The compressed difficulty in hexadecimal
    #[serde(with = "crate::serde_hex")]
    pub bits: Vec<u8>,
    /// The previous block hash the current template is mining on
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: bitcoin::BlockHash,
    /// The current time as seen by the server (recommended for block time)
    /// Note: this is not necessarily the system clock, and must fall within
    /// the mintime/maxtime rules. Expressed as UNIX timestamp.
    #[serde(rename = "curtime")]
    pub current_time: u64,
    /// The height of the block we will be mining: `current height + 1`
    pub height: u64,
    /// Block sigops limit
    #[serde(rename = "sigoplimit")]
    pub sigop_limit: u32,
    /// Block size limit
    #[serde(rename = "sizelimit")]
    pub size_limit: u32,
    /// Block weight limit
    #[serde(rename = "weightlimit")]
    pub weight_limit: u32,
    /// Block header version
    pub version: u32,
    /// Block rules that are to be enforced
    pub rules: Vec<GetBlockTemplateResultRules>,
    /// List of features the Bitcoin Core getblocktemplate implementation supports
    pub capabilities: Vec<GetBlockTemplateResultCapabilities>,
    /// Set of pending, supported versionbit (BIP 9) softfork deployments
    #[serde(rename = "vbavailable")]
    pub version_bits_available: HashMap<String, u32>,
    /// Bit mask of versionbits the server requires set in submissions
    #[serde(rename = "vbrequired")]
    pub version_bits_required: u32,
    /// Id used in longpoll requests for this template.
    pub longpollid: String,
    /// List of transactions included in the template block
    pub transactions: Vec<GetBlockTemplateResultTransaction>,
    /// The signet challenge. Only set if mining on a signet, otherwise empty
    #[serde(default, with = "bitcoin::script::ScriptBuf")]
    pub signet_challenge: bitcoin::script::ScriptBuf,
    /// The default witness commitment included in an OP_RETURN output of the
    /// coinbase transactions. Only set when mining on a network where SegWit
    /// is activated.
    #[serde(with = "bitcoin::script::ScriptBuf", default)]
    pub default_witness_commitment: bitcoin::script::ScriptBuf,
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
}

/// Models a single transaction entry in the result of "getblocktemplate"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateResultTransaction {
    /// The transaction id
    pub txid: bitcoin::Txid,
    /// The wtxid of the transaction
    #[serde(rename = "hash")]
    pub wtxid: bitcoin::Wtxid,
    /// The serilaized transaction bytes
    #[serde(with = "crate::serde_hex", rename = "data")]
    pub raw_tx: Vec<u8>,
    // The transaction fee
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub fee: Amount,
    /// Transaction sigops
    pub sigops: u32,
    /// Transaction weight in weight units
    pub weight: usize,
    /// Transactions that must be in present in the final block if this one is.
    /// Indexed by a 1-based index in the `GetBlockTemplateResult.transactions`
    /// list
    pub depends: Vec<u32>,
}

impl GetBlockTemplateResultTransaction {
    pub fn transaction(&self) -> Result<Transaction, encode::Error> {
        encode::deserialize(&self.raw_tx)
    }
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
    #[serde(with = "bitcoin::amount::serde::as_btc")]
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
    pub change_address: Option<Address<NetworkUnchecked>>,
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
        with = "bitcoin::amount::serde::as_btc::opt"
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
    pub psbt: Option<String>,
    #[serde(default, with = "crate::serde_hex::opt")]
    pub hex: Option<Vec<u8>>,
    pub complete: bool,
}

/// Model for decode transaction
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct DecodeRawTransactionResult {
    pub txid: bitcoin::Txid,
    pub hash: bitcoin::Wtxid,
    pub size: u32,
    pub vsize: u32,
    pub weight: u32,
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

impl FinalizePsbtResult {
    pub fn transaction(&self) -> Option<Result<Transaction, encode::Error>> {
        self.hex.as_ref().map(|h| encode::deserialize(h))
    }
}

// Custom types for input arguments.

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum EstimateMode {
    Unset,
    Economical,
    Conservative,
}

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
#[derive(Serialize, Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRawTransactionInput {
    pub txid: bitcoin::Txid,
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
    /// The fee rate to pay per kvB. NB. This field is converted to camelCase
    /// when serialized, so it is receeived by fundrawtransaction as `feeRate`,
    /// which fee rate per kvB, and *not* `fee_rate`, which is per vB.
    #[serde(
        with = "bitcoin::amount::serde::as_btc::opt",
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

#[derive(Deserialize, Clone, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionResult {
    #[serde(with = "crate::serde_hex")]
    pub hex: Vec<u8>,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub fee: Amount,
    #[serde(rename = "changepos")]
    pub change_position: i32,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug, Serialize)]
pub struct GetBalancesResultEntry {
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub trusted: Amount,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub untrusted_pending: Amount,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub immature: Amount,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug, Serialize)]
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
#[derive(Serialize, Clone, PartialEq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionInput {
    pub txid: bitcoin::Txid,
    pub vout: u32,
    pub script_pub_key: ScriptBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<ScriptBuf>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "bitcoin::amount::serde::as_btc::opt"
    )]
    pub amount: Option<Amount>,
}

/// Used to represent UTXO set hash type
#[derive(Clone, Serialize, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxOutSetHashType {
    HashSerialized2,
    Muhash,
    None,
}

/// Used to specify a block hash or a height
#[derive(Clone, Serialize, PartialEq, Eq, Debug, Deserialize)]
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
    /// The number of transactions with unspent outputs (not available when coinstatsindex is used)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transactions: Option<u64>,
    /// The number of unspent transaction outputs
    #[serde(rename = "txouts")]
    pub tx_outs: u64,
    /// A meaningless metric for UTXO set size
    pub bogosize: u64,
    /// The serialized hash (only present if 'hash_serialized_2' hash_type is chosen)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_serialized_2: Option<sha256::Hash>,
    /// The serialized hash (only present if 'muhash' hash_type is chosen)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub muhash: Option<sha256::Hash>,
    /// The estimated size of the chainstate on disk (not available when coinstatsindex is used)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_size: Option<u64>,
    /// The total amount
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub total_amount: Amount,
    /// The total amount of coins permanently excluded from the UTXO set (only available if coinstatsindex is used)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "bitcoin::amount::serde::as_btc::opt"
    )]
    pub total_unspendable_amount: Option<Amount>,
    /// Info on amounts in the block at this block height (only available if coinstatsindex is used)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_info: Option<BlockInfo>,
}

/// Info on amounts in the block at the block height of the `gettxoutsetinfo` call (only available if coinstatsindex is used)
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockInfo {
    /// Amount of previous outputs spent
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub prevout_spent: Amount,
    /// Output size of the coinbase transaction
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub coinbase: Amount,
    /// Newly-created outputs
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub new_outputs_ex_coinbase: Amount,
    /// Amount of unspendable outputs
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub unspendable: Amount,
    /// Detailed view of the unspendable categories
    pub unspendables: Unspendables,
}

/// Detailed view of the unspendable categories
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Unspendables {
    /// Unspendable coins from the Genesis block
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub genesis_block: Amount,
    /// Transactions overridden by duplicates (no longer possible with BIP30)
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub bip30: Amount,
    /// Amounts sent to scripts that are unspendable (for example OP_RETURN outputs)
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub scripts: Amount,
    /// Fee rewards that miners did not claim in their coinbase transaction
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub unclaimed_rewards: Amount,
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
    Bech32m,
}

/// Used to represent arguments that can either be an address or a public key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PubKeyOrAddress<'a> {
    Address(&'a Address),
    PubKey(&'a PublicKey),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
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
    pub best_block_hash: Option<bitcoin::BlockHash>,
    pub unspents: Vec<Utxo>,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub total_amount: bitcoin::Amount,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Utxo {
    pub txid: bitcoin::Txid,
    pub vout: u32,
    pub script_pub_key: bitcoin::ScriptBuf,
    #[serde(rename = "desc")]
    pub descriptor: String,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub amount: bitcoin::Amount,
    pub height: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct IndexStatus {
    pub synced: bool,
    pub best_block_height: u32,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct GetIndexInfoResult {
    pub txindex: Option<IndexStatus>,
    pub coinstatsindex: Option<IndexStatus>,
    #[serde(rename = "basic block filter index")]
    pub basic_block_filter_index: Option<IndexStatus>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetZmqNotificationsResult {
    #[serde(rename = "type")]
    pub notification_type: String,
    pub address: String,
    pub hwm: u64,
}

impl<'a> serde::Serialize for PubKeyOrAddress<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match *self {
            PubKeyOrAddress::Address(a) => serde::Serialize::serialize(a, serializer),
            PubKeyOrAddress::PubKey(k) => serde::Serialize::serialize(k, serializer),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_softfork_type() {
        let buried: SoftforkType = serde_json::from_str("\"buried\"").unwrap();
        assert_eq!(buried, SoftforkType::Buried);
        let bip9: SoftforkType = serde_json::from_str("\"bip9\"").unwrap();
        assert_eq!(bip9, SoftforkType::Bip9);
        let other: SoftforkType = serde_json::from_str("\"bip8\"").unwrap();
        assert_eq!(other, SoftforkType::Other);
    }
}
