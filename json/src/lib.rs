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

pub extern crate bitcoin;
#[allow(unused)]
#[macro_use] // `macro_use` is needed for v1.24.0 compilation.
extern crate serde;
extern crate serde_json;

use std::collections::HashMap;

use bitcoin::consensus::encode;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::util::{bip158, bip32};
use bitcoin::{Address, Amount, SignedAmount, PrivateKey, PublicKey, Script, Transaction};
use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};

//TODO(stevenroose) consider using a Time type

/// A module used for serde serialization of bytes in hexadecimal format.
///
/// The module is compatible with the serde attribute.
pub mod serde_hex {
    use bitcoin::hashes::hex::{FromHex, ToHex};
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let hex_str: String = ::serde::Deserialize::deserialize(d)?;
        Ok(FromHex::from_hex(&hex_str).map_err(D::Error::custom)?)
    }

    pub mod opt {
        use bitcoin::hashes::hex::{FromHex, ToHex};
        use serde::de::Error;
        use serde::{Deserializer, Serializer};

        pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match *b {
                None => s.serialize_none(),
                Some(ref b) => s.serialize_str(&b.to_hex()),
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
    pub time_offset: usize,
    pub connections: usize,
    #[serde(rename = "networkactive")]
    pub network_active: bool,
    pub networks: Vec<GetNetworkInfoResultNetwork>,
    #[serde(rename = "relayfee", with = "bitcoin::util::amount::serde::as_btc")]
    pub relay_fee: Amount,
    #[serde(rename = "incrementalfee", with = "bitcoin::util::amount::serde::as_btc")]
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

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockResult {
    pub hash: bitcoin::BlockHash,
    pub confirmations: u32,
    pub size: usize,
    pub strippedsize: Option<usize>,
    pub weight: usize,
    pub height: usize,
    pub version: u32,
    #[serde(default, with = "::serde_hex::opt")]
    pub version_hex: Option<Vec<u8>>,
    pub merkleroot: bitcoin::TxMerkleNode,
    pub tx: Vec<bitcoin::Txid>,
    pub time: usize,
    pub mediantime: Option<usize>,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    #[serde(with = "::serde_hex")]
    pub chainwork: Vec<u8>,
    pub n_tx: usize,
    pub previousblockhash: Option<bitcoin::BlockHash>,
    pub nextblockhash: Option<bitcoin::BlockHash>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResult {
    pub hash: bitcoin::BlockHash,
    pub confirmations: u32,
    pub height: usize,
    pub version: u32,
    #[serde(default, with = "::serde_hex::opt")]
    pub version_hex: Option<Vec<u8>>,
    #[serde(rename = "merkleroot")]
    pub merkle_root: bitcoin::TxMerkleNode,
    pub time: usize,
    #[serde(rename = "mediantime")]
    pub median_time: Option<usize>,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    #[serde(with = "::serde_hex")]
    pub chainwork: Vec<u8>,
    pub n_tx: usize,
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: Option<bitcoin::BlockHash>,
    #[serde(rename = "nextblockhash")]
    pub next_block_hash: Option<bitcoin::BlockHash>,
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
    #[serde(with = "::serde_hex")]
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
    pub sequence: u32,
    /// The raw scriptSig in case of a coinbase tx.
    #[serde(default, with = "::serde_hex::opt")]
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
    #[serde(with = "::serde_hex")]
    pub hex: Vec<u8>,
    pub req_sigs: Option<usize>,
    #[serde(rename = "type")]
    pub type_: Option<ScriptPubkeyType>,
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
    #[serde(with = "bitcoin::util::amount::serde::as_btc")]
    pub value: Amount,
    pub n: u32,
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResult {
    #[serde(rename = "in_active_chain")]
    pub in_active_chain: Option<bool>,
    #[serde(with = "::serde_hex")]
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
    pub header: bitcoin::FilterHash,
    #[serde(with = "::serde_hex")]
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

/// Enum to represent the BIP125 replaceable status for a transaction.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetTransactionResultDetailCategory {
    Send,
    Receive,
    Generate,
    Immature,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetTransactionResultDetail {
    pub address: Address,
    pub category: GetTransactionResultDetailCategory,
    #[serde(with = "bitcoin::util::amount::serde::as_btc")]
    pub amount: SignedAmount,
    pub label: Option<String>,
    pub vout: u32,
    #[serde(default, with = "bitcoin::util::amount::serde::as_btc::opt")]
    pub fee: Option<SignedAmount>,
    pub abandoned: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct WalletTxInfo {
    pub confirmations: i32,
    pub blockhash: Option<bitcoin::BlockHash>,
    pub blockindex: Option<usize>,
    pub blocktime: Option<u64>,
    pub txid: bitcoin::Txid,
    pub time: u64,
    pub timereceived: u64,
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: Bip125Replaceable,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetTransactionResult {
    #[serde(flatten)]
    pub info: WalletTxInfo,
    #[serde(with = "bitcoin::util::amount::serde::as_btc")]
    pub amount: SignedAmount,
    #[serde(default, with = "bitcoin::util::amount::serde::as_btc::opt")]
    pub fee: Option<SignedAmount>,
    pub details: Vec<GetTransactionResultDetail>,
    #[serde(with = "::serde_hex")]
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

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTxOutResult {
    pub bestblock: bitcoin::BlockHash,
    pub confirmations: u32,
    #[serde(with = "bitcoin::util::amount::serde::as_btc")]
    pub value: Amount,
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
    pub coinbase: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentQueryOptions {
    #[serde(
        rename = "minimumAmount",
        with = "bitcoin::util::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_amount: Option<Amount>,
    #[serde(
        rename = "maximumAmount",
        with = "bitcoin::util::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub maximum_amount: Option<Amount>,
    #[serde(rename = "maximumCount", skip_serializing_if = "Option::is_none")]
    pub maximum_count: Option<usize>,
    #[serde(
        rename = "minimumSumAmount",
        with = "bitcoin::util::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_sum_amount: Option<Amount>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentResultEntry {
    pub txid: bitcoin::Txid,
    pub vout: u32,
    pub address: Option<Address>,
    pub label: Option<String>,
    pub redeem_script: Option<Script>,
    pub witness_script: Option<Script>,
    pub script_pub_key: Script,
    #[serde(with = "bitcoin::util::amount::serde::as_btc")]
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
    pub address: Address,
    #[serde(with = "bitcoin::util::amount::serde::as_btc")]
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
    pub script_sig: Script,
    pub sequence: u32,
    pub error: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionResult {
    #[serde(with = "::serde_hex")]
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
    pub threshold: u32,
    pub elapsed: u32,
    pub count: u32,
    pub possible: bool,
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
    Witness_Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetAddressInfoResultEmbedded {
    pub address: Address,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: Script,
    #[serde(rename = "is_script")]
    pub is_script: Option<bool>,
    #[serde(rename = "is_witness")]
    pub is_witness: Option<bool>,
    pub witness_version: Option<u32>,
    #[serde(with = "::serde_hex")]
    pub witness_program: Vec<u8>,
    pub script: Option<ScriptPubkeyType>,
    /// The redeemscript for the p2sh address.
    #[serde(default, with = "::serde_hex::opt")]
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
    pub hd_seed_id: Option<bitcoin::XpubIdentifier>,
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
pub struct GetAddressInfoResultLabel {
    pub name: String,
    pub purpose: GetAddressInfoResultLabelPurpose,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetAddressInfoResult {
    pub address: Address,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: Script,
    #[serde(rename = "ismine")]
    pub is_mine: Option<bool>,
    #[serde(rename = "iswatchonly")]
    pub is_watchonly: Option<bool>,
    #[serde(rename = "isscript")]
    pub is_script: Option<bool>,
    #[serde(rename = "iswitness")]
    pub is_witness: Option<bool>,
    pub witness_version: Option<u32>,
    #[serde(default, with = "::serde_hex::opt")]
    pub witness_program: Option<Vec<u8>>,
    pub script: Option<ScriptPubkeyType>,
    /// The redeemscript for the p2sh address.
    #[serde(default, with = "::serde_hex::opt")]
    pub hex: Option<Vec<u8>>,
    pub pubkeys: Option<Vec<PublicKey>>,
    #[serde(rename = "sigsrequired")]
    pub n_signatures_required: Option<usize>,
    pub pubkey: Option<PublicKey>,
    /// Information about the address embedded in P2SH or P2WSH, if relevant and known.
    pub embedded: Option<GetAddressInfoResultEmbedded>,
    #[serde(rename = "is_compressed")]
    pub is_compressed: Option<bool>,
    pub label: String,
    pub timestamp: Option<u64>,
    #[serde(rename = "hdkeypath")]
    pub hd_key_path: Option<bip32::DerivationPath>,
    #[serde(rename = "hdseedid")]
    pub hd_seed_id: Option<bitcoin::XpubIdentifier>,
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
    #[serde(rename = "chainwork", with = "::serde_hex")]
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
    /// Any network and blockchain warnings.
    pub warnings: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ImportMultiRequestScriptPubkey<'a> {
    Address(&'a Address),
    Script(&'a Script),
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
                };
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
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize)]
pub struct ImportMultiRequest<'a> {
    pub timestamp: u64,
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
    /// The services offered
    // TODO: use a type for services
    pub services: String,
    /// Whether peer has asked us to relay transactions to it
    pub relaytxes: bool,
    /// The time in seconds since epoch (Jan 1 1970 GMT) of the last send
    pub lastsend: u64,
    /// The time in seconds since epoch (Jan 1 1970 GMT) of the last receive
    pub lastrecv: u64,
    /// The total bytes sent
    pub bytessent: u64,
    /// The total bytes received
    pub bytesrecv: u64,
    /// The connection time in seconds since epoch (Jan 1 1970 GMT)
    pub conntime: u64,
    /// The time offset in seconds
    pub timeoffset: i64,
    /// ping time (if available)
    pub pingtime: f64,
    /// minimum observed ping time (if any at all)
    pub minping: f64,
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
    pub addnode: bool,
    /// The starting height (block) of the peer
    pub startingheight: u64,
    /// The ban score
    pub banscore: i64,
    /// The last header we have in common with this peer
    pub synced_headers: i64,
    /// The last block we have in common with this peer
    pub synced_blocks: i64,
    /// The heights of blocks we're currently asking from this peer
    pub inflight: Vec<u64>,
    /// Whether the peer is whitelisted
    pub whitelisted: bool,
    #[serde(rename = "minfeefilter", default, with = "bitcoin::util::amount::serde::as_btc::opt")]
    pub min_fee_filter: Option<Amount>,
    /// The total bytes sent aggregated by message type
    pub bytessent_per_msg: HashMap<String, u64>,
    /// The total bytes received aggregated by message type
    pub bytesrecv_per_msg: HashMap<String, u64>,
}

/// Models the result of "estimatesmartfee"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EstimateSmartFeeResult {
    /// Estimate fee rate in BTC/kB.
    #[serde(
        default,
        rename = "feerate",
        skip_serializing_if = "Option::is_none",
        with = "bitcoin::util::amount::serde::as_btc::opt"
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
    pub checksum: String,
    #[serde(rename = "isrange")]
    pub is_range: bool,
    #[serde(rename = "issolvable")]
    pub is_solvable: bool,
    #[serde(rename = "hasprivatekeys")]
    pub has_private_keys: bool,
}

/// Models the result of "walletcreatefundedpsbt"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct WalletCreateFundedPsbtResult {
    pub psbt: String,
    #[serde(with = "bitcoin::util::amount::serde::as_btc")]
    pub fee: Amount,
    #[serde(rename = "changepos")]
    pub change_position: i32,
}

/// Models the request for "walletcreatefundedpsbt"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Default)]
pub struct WalletCreateFundedPsbtOptions {
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
        with = "bitcoin::util::amount::serde::as_btc::opt"
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
    #[serde(default, with = "::serde_hex::opt")]
    pub hex: Option<Vec<u8>>,
    pub complete: bool,
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

/// A wrapper around bitcoin::SigHashType that will be serialized
/// according to what the RPC expects.
pub struct SigHashType(bitcoin::SigHashType);

impl From<bitcoin::SigHashType> for SigHashType {
    fn from(sht: bitcoin::SigHashType) -> SigHashType {
        SigHashType(sht)
    }
}

impl serde::Serialize for SigHashType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self.0 {
            bitcoin::SigHashType::All => "ALL",
            bitcoin::SigHashType::None => "NONE",
            bitcoin::SigHashType::Single => "SINGLE",
            bitcoin::SigHashType::AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
            bitcoin::SigHashType::NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
            bitcoin::SigHashType::SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
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

#[derive(Serialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionOptions {
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
        with = "bitcoin::util::amount::serde::as_btc::opt",
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
    #[serde(with = "::serde_hex")]
    pub hex: Vec<u8>,
    #[serde(with = "bitcoin::util::amount::serde::as_btc")]
    pub fee: Amount,
    #[serde(rename = "changepos")]
    pub change_position: i32,
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
    pub txid: bitcoin::Txid,
    pub vout: u32,
    pub script_pub_key: Script,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<Script>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "bitcoin::util::amount::serde::as_btc::opt"
    )]
    pub amount: Option<Amount>,
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
