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

#[macro_use]
extern crate serde_derive;
extern crate bitcoin;
extern crate bitcoin_amount;
extern crate bitcoin_hashes;
extern crate hex;
extern crate num_bigint;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;

pub mod getters;
pub use getters::*;

use std::str::FromStr;

use bitcoin::blockdata::script::Script;
use bitcoin::util::address::Address;
use bitcoin_hashes::sha256d;
use bitcoin_amount::Amount;
use num_bigint::BigUint;
use secp256k1::PublicKey;
use serde::de::Error as SerdeError;
use serde::Deserialize;
use serde_json::Value;

//TODO(stevenroose) consider using a Time type

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMultiSigAddressResult {
    pub address: Address,
    pub redeem_script: Script,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockResult {
    pub hash: sha256d::Hash,
    pub confirmations: usize,
    pub size: usize,
    pub strippedsize: Option<usize>,
    pub weight: usize,
    pub height: usize,
    pub version: u32,
    pub version_hex: Option<String>,
    pub merkleroot: sha256d::Hash,
    pub tx: Vec<sha256d::Hash>,
    pub time: usize,
    pub mediantime: Option<usize>,
    pub nonce: u32,
    pub bits: String,
    #[serde(deserialize_with = "deserialize_difficulty")]
    pub difficulty: BigUint,
    pub chainwork: String,
    pub n_tx: usize,
    pub previousblockhash: Option<sha256d::Hash>,
    pub nextblockhash: Option<sha256d::Hash>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResult {
    pub hash: sha256d::Hash,
    pub confirmations: usize,
    pub height: usize,
    pub version: u32,
    pub version_hex: Option<String>,
    pub merkleroot: sha256d::Hash,
    pub time: usize,
    pub mediantime: Option<usize>,
    pub nonce: u32,
    pub bits: String,
    #[serde(deserialize_with = "deserialize_difficulty")]
    pub difficulty: BigUint,
    pub chainwork: String,
    pub n_tx: usize,
    pub previousblockhash: Option<sha256d::Hash>,
    pub nextblockhash: Option<sha256d::Hash>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetMiningInfoResult {
    pub blocks: u32,
    pub currentblockweight: u64,
    pub currentblocktx: usize,
    #[serde(deserialize_with = "deserialize_difficulty")]
    pub difficulty: BigUint,
    pub networkhashps: f64,
    pub pooledtx: usize,
    pub chain: String,
    pub warnings: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVinScriptSig {
    pub asm: String,
    pub hex: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVin {
    pub txid: sha256d::Hash,
    pub vout: u32,
    pub script_sig: GetRawTransactionResultVinScriptSig,
    pub sequence: u32,
    #[serde(default, deserialize_with = "deserialize_hex_array_opt")]
    pub txinwitness: Option<Vec<Vec<u8>>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVoutScriptPubKey {
    pub asm: String,
    pub hex: String,
    pub req_sigs: usize,
    #[serde(rename = "type")]
    pub type_: String, //TODO(stevenroose) consider enum
    pub addresses: Vec<Address>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVout {
    #[serde(deserialize_with = "deserialize_amount")]
    pub value: Amount,
    pub n: u32,
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResult {
    #[serde(rename = "in_active_chain")]
    pub in_active_chain: Option<bool>,
    pub hex: String,
    pub txid: sha256d::Hash,
    pub hash: sha256d::Hash,
    pub size: usize,
    pub vsize: usize,
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<GetRawTransactionResultVin>,
    pub vout: Vec<GetRawTransactionResultVout>,
    pub blockhash: sha256d::Hash,
    pub confirmations: usize,
    pub time: usize,
    pub blocktime: usize,
}

/// Enum to represent the BIP125 replacable status for a transaction.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Bip125Replaceable {
    Yes,
    No,
    Unknown,
}

/// Enum to represent the BIP125 replacable status for a transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum GetTransactionResultDetailCategory {
    Send,
    Receive,
}

impl<'de> ::serde::Deserialize<'de> for GetTransactionResultDetailCategory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_ref() {
            "send" => Ok(GetTransactionResultDetailCategory::Send),
            "receive" => Ok(GetTransactionResultDetailCategory::Receive),
            v => Err(D::Error::custom(&format!("wrong value for 'detail' field: {}", v))),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionResultDetail {
    pub address: Address,
    pub category: GetTransactionResultDetailCategory,
    #[serde(deserialize_with = "deserialize_amount")]
    pub amount: Amount,
    pub label: String,
    pub vout: u32,
    #[serde(default, deserialize_with = "deserialize_amount_opt")]
    pub fee: Option<Amount>,
    pub abandoned: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionResult {
    #[serde(deserialize_with = "deserialize_amount")]
    pub amount: Amount,
    #[serde(default, deserialize_with = "deserialize_amount_opt")]
    pub fee: Option<Amount>,
    pub confirmations: usize,
    pub blockhash: sha256d::Hash,
    pub blockindex: usize,
    pub blocktime: u64,
    pub txid: sha256d::Hash,
    pub time: u64,
    pub timereceived: u64,
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: Bip125Replaceable,
    pub details: Vec<GetTransactionResultDetail>,
    pub hex: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTxOutResult {
    pub bestblock: sha256d::Hash,
    pub confirmations: usize,
    #[serde(deserialize_with = "deserialize_amount")]
    pub value: Amount,
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
    pub coinbase: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentResult {
    pub txid: sha256d::Hash,
    pub vout: u32,
    pub address: Address,
    pub script_pub_key: Script,
    #[serde(deserialize_with = "deserialize_amount")]
    pub amount: Amount,
    pub confirmations: usize,
    pub redeem_script: Option<Script>,
    pub spendable: bool,
    pub solvable: bool,
    pub safe: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionResultError {
    pub txid: sha256d::Hash,
    pub vout: u32,
    pub script_sig: Script,
    pub sequence: u32,
    pub error: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionResult {
    pub hex: String,
    pub complete: bool,
    #[serde(default)]
    pub errors: Vec<SignRawTransactionResultError>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TestMempoolAccept {
    pub txid: String,
    pub allowed: bool,
    #[serde(rename = "reject-reason")]
    pub reject_reason: String,
}

/// Models the result of "getblockchaininfo"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetBlockchainInfoResult {
    // TODO: Use Network from rust-bitcoin
    /// Current network name as defined in BIP70 (main, test, regtest)
    pub chain: String,
    /// The current number of blocks processed in the server
    pub blocks: u64,
    /// The current number of headers we have validated
    pub headers: u64,
    /// The hash of the currently best block
    pub bestblockhash: sha256d::Hash,
    /// The current difficulty
    pub difficulty: f64,
    /// Median time for the current best block
    pub mediantime: u64,
    /// Estimate of verification progress [0..1]
    pub verificationprogress: f64,
    /// Estimate of whether this node is in Initial Block Download mode
    pub initialblockdownload: bool,
    /// Total amount of work in active chain, in hexadecimal
    pub chainwork: String,
    /// The estimated size of the block and undo files on disk
    pub size_on_disk: u64,
    /// If the blocks are subject to pruning
    pub pruned: bool,
    /// Lowest-height complete block stored (only present if pruning is enabled)
    pub pruneheight: Option<u64>,
    /// Whether automatic pruning is enabled (only present if pruning is enabled)
    pub automatic_pruning: Option<bool>,
    /// The target size used by pruning (only present if automatic pruning is enabled)
    pub prune_target_size: Option<u64>,
    /// Status of softforks in progress
    pub softforks: Vec<Softfork>,
    // TODO: add a type?
    /// Status of BIP9 softforks in progress
    pub bip9_softforks: Value,
    /// Any network and blockchain warnings.
    pub warnings: String,
}

/// Status of a softfork
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Softfork {
    /// Name of softfork
    pub id: String,
    /// Block version
    pub version: u64,
    /// Progress toward rejecting pre-softfork blocks
    pub reject: RejectStatus,
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
    pub addrlocal: String,
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
    pub timeoffset: u64,
    /// ping time (if available)
    pub pingtime: u64,
    /// minimum observed ping time (if any at all)
    pub minping: u64,
    /// ping wait (if non-zero)
    pub pingwait: u64,
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
    pub synced_headers: u64,
    /// The last block we have in common with this peer
    pub synced_blocks: u64,
    /// The heights of blocks we're currently asking from this peer
    pub inflight: Vec<u64>,
    /// Whether the peer is whitelisted
    pub whitelisted: bool,
    /// The total bytes sent aggregated by message type
    // TODO: use a type for bytessent_per_msg
    pub bytessent_per_msg: Value,
    /// The total bytes received aggregated by message type
    // TODO: use a type for bytesrecv_per_msg
    pub bytesrecv_per_msg: Value,
}

/// Models the result of "estimatesmartfee"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EstimateSmartFeeResult {
    /// Estimate fee rate in BTC/kB.
    pub feerate: Option<Value>,
    /// Errors encountered during processing.
    pub errors: Option<Vec<String>>,
    /// Block number where estimate was found.
    pub blocks: i64,
}

/// Models the result of "waitfornewblock", and "waitforblock"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockRef {
    pub hash: sha256d::Hash,
    pub height: u64,
}

// Custom types for input arguments.

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum EstimateMode {
    Unset,
    Economical,
    Conservative,
}

impl FromStr for EstimateMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UNSET" => Ok(EstimateMode::Unset),
            "ECONOMICAL" => Ok(EstimateMode::Economical),
            "CONSERVATIVE" => Ok(EstimateMode::Conservative),
            _ => Err(()),
        }
    }
}

impl ::serde::Serialize for EstimateMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        let s = match *self {
            EstimateMode::Unset => "UNSET",
            EstimateMode::Economical => "ECONOMICAL",
            EstimateMode::Conservative => "CONSERVATIVE",
        };

        serializer.serialize_str(s)
    }
}

/// A wrapper around &[u8] that will be serialized as hexadecimal.
/// If you have an `&[u8]`, you can `.into()` it into `HexBytes`.
pub struct HexBytes<'a>(&'a [u8]);

impl<'a> From<&'a [u8]> for HexBytes<'a> {
    fn from(b: &'a [u8]) -> HexBytes<'a> {
        HexBytes(b)
    }
}

impl<'a> serde::Serialize for HexBytes<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
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
    pub txid: sha256d::Hash,
    pub vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
}

// Used for signrawtransaction argument.
#[derive(Serialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionInput {
    pub txid: sha256d::Hash,
    pub vout: u32,
    pub script_pub_key: Script,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<Script>,
    pub amount: f64,
}

/// Used to represent an address type.
pub enum AddressType {
    Legacy,
    P2shSegwit,
    Bech32,
}

impl serde::Serialize for AddressType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match *self {
            AddressType::Legacy => "legacy",
            AddressType::P2shSegwit => "p2sh-segwit",
            AddressType::Bech32 => "bech32",
        })
    }
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

/// deserialize_amount deserializes a BTC-denominated floating point Bitcoin amount into the
/// Amount type.
fn deserialize_amount<'de, D>(deserializer: D) -> Result<Amount, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Amount::from_btc(f64::deserialize(deserializer)?))
}

/// deserialize_amount_opt deserializes a BTC-denominated floating point Bitcoin amount into an
/// Option of the Amount type.
fn deserialize_amount_opt<'de, D>(deserializer: D) -> Result<Option<Amount>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Amount::from_btc(f64::deserialize(deserializer)?)))
}

fn deserialize_difficulty<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = f64::deserialize(deserializer)?.to_string();
    let real = match s.split('.').nth(0) {
        Some(r) => r,
        None => return Err(D::Error::custom(&format!("error parsing difficulty: {}", s))),
    };
    BigUint::from_str(real)
        .map_err(|_| D::Error::custom(&format!("error parsing difficulty: {}", s)))
}

///// deserialize_hex deserializes a hex-encoded byte array.
//fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
//		where D: serde::Deserializer<'de> {
//	let h = String::deserialize(deserializer)?;
//	hex::decode(&h).map_err(|_| D::Error::custom(&format!("error parsing hex: {}", h)))
//}

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
        res.push(hex::decode(h).map_err(D::Error::custom)?);
    }
    Ok(Some(res))
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use bitcoin_hashes::hex::FromHex;

    macro_rules! deserializer {
        ($j:expr) => {
            &mut serde_json::Deserializer::from_str($j)
        };
    }

    macro_rules! hash {
        ($h:expr) => {
            sha256d::Hash::from_hex($h).unwrap()
        };
    }

    macro_rules! addr {
        ($a:expr) => {
            Address::from_str($a).unwrap()
        };
    }

    macro_rules! script {
        ($s:expr) => {
            serde_json::from_str(&format!(r#""{}""#, $s)).unwrap()
        };
    }

    #[test]
    fn test_AddMultiSigAddressResult() {
        let expected = AddMultiSigAddressResult {
			address: addr!("2N3Cvw3s23W43MXnW28DKpuDGeXV147KTzc"),
			redeem_script: script!("51210330aa51b444e2bac981235a0056112385057492c6cd06936af410c5af27c1f9462103dae74774a6cd35d948ee60bc7a1b35fdaed7b54698762e963e3677f795c7ad2a52ae"),
		};
        let json = r#"
			{
			  "address": "2N3Cvw3s23W43MXnW28DKpuDGeXV147KTzc",
			  "redeemScript": "51210330aa51b444e2bac981235a0056112385057492c6cd06936af410c5af27c1f9462103dae74774a6cd35d948ee60bc7a1b35fdaed7b54698762e963e3677f795c7ad2a52ae"
			}
		"#;
        assert_eq!(expected, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_GetBlockResult() {
        let expected = GetBlockResult {
            hash: hash!("000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820"),
            confirmations: 1414401,
            size: 190,
            strippedsize: Some(190),
            weight: 760,
            height: 2,
            version: 1,
            version_hex: Some("00000001".into()),
            merkleroot: hash!("20222eb90f5895556926c112bb5aa0df4ab5abc3107e21a6950aec3b2e3541e2"),
            tx: vec![hash!("20222eb90f5895556926c112bb5aa0df4ab5abc3107e21a6950aec3b2e3541e2")],
            time: 1296688946,
            mediantime: Some(1296688928),
            nonce: 875942400,
            bits: "1d00ffff".into(),
            difficulty: 1u64.into(),
            chainwork: "0000000000000000000000000000000000000000000000000000000300030003".into(),
            n_tx: 1,
            previousblockhash: Some(hash!(
                "00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206"
            )),
            nextblockhash: Some(hash!(
                "000000008b896e272758da5297bcd98fdc6d97c9b765ecec401e286dc1fdbe10"
            )),
        };
        let json = r#"
			{
			  "hash": "000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820",
			  "confirmations": 1414401,
			  "strippedsize": 190,
			  "size": 190,
			  "weight": 760,
			  "height": 2,
			  "version": 1,
			  "versionHex": "00000001",
			  "merkleroot": "20222eb90f5895556926c112bb5aa0df4ab5abc3107e21a6950aec3b2e3541e2",
			  "tx": [
				"20222eb90f5895556926c112bb5aa0df4ab5abc3107e21a6950aec3b2e3541e2"
			  ],
			  "time": 1296688946,
			  "mediantime": 1296688928,
			  "nonce": 875942400,
			  "bits": "1d00ffff",
			  "difficulty": 1,
			  "chainwork": "0000000000000000000000000000000000000000000000000000000300030003",
			  "nTx": 1,
			  "previousblockhash": "00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206",
			  "nextblockhash": "000000008b896e272758da5297bcd98fdc6d97c9b765ecec401e286dc1fdbe10"
			}
		"#;
        assert_eq!(expected, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_GetBlockHeaderResult() {
        let expected = GetBlockHeaderResult {
            hash: hash!("00000000000000039dc06adbd7666a8d1df9acf9d0329d73651b764167d63765"),
            confirmations: 29341,
            height: 1384958,
            version: 536870912,
            version_hex: Some("20000000".into()),
            merkleroot: hash!("33d8a6f622182a4e844022bbc8aa51c63f6476708ad5cc5c451f2933753440d7"),
            time: 1534935138,
            mediantime: Some(1534932055),
            nonce: 871182973,
            bits: "1959273b".into(),
            difficulty: 48174374u64.into(),
            chainwork: "0000000000000000000000000000000000000000000000a3c78921878ecbafd4".into(),
            n_tx: 2647,
            previousblockhash: Some(hash!(
                "000000000000002937dcaffd8367cfb05cd9ef2e3bd7a081de82696f70e719d9"
            )),
            nextblockhash: Some(hash!(
                "00000000000000331dddb553312687a4be62635ad950cde36ebc977c702d2791"
            )),
        };
        let json = r#"
			{
			  "hash": "00000000000000039dc06adbd7666a8d1df9acf9d0329d73651b764167d63765",
			  "confirmations": 29341,
			  "height": 1384958,
			  "version": 536870912,
			  "versionHex": "20000000",
			  "merkleroot": "33d8a6f622182a4e844022bbc8aa51c63f6476708ad5cc5c451f2933753440d7",
			  "time": 1534935138,
			  "mediantime": 1534932055,
			  "nonce": 871182973,
			  "bits": "1959273b",
			  "difficulty": 48174374.44122773,
			  "chainwork": "0000000000000000000000000000000000000000000000a3c78921878ecbafd4",
			  "nTx": 2647,
			  "previousblockhash": "000000000000002937dcaffd8367cfb05cd9ef2e3bd7a081de82696f70e719d9",
			  "nextblockhash": "00000000000000331dddb553312687a4be62635ad950cde36ebc977c702d2791"
			}
		"#;
        assert_eq!(expected, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_GetMiningInfoResult() {
        let expected = GetMiningInfoResult {
            blocks: 1415011,
            currentblockweight: 0,
            currentblocktx: 0,
            difficulty: 1u32.into(),
            networkhashps: 11970022568515.56,
            pooledtx: 110,
            chain: "test".into(),
            warnings: "Warning: unknown new rules activated (versionbit 28)".into(),
        };
        let json = r#"
			{
			  "blocks": 1415011,
			  "currentblockweight": 0,
			  "currentblocktx": 0,
			  "difficulty": 1,
			  "networkhashps": 11970022568515.56,
			  "pooledtx": 110,
			  "chain": "test",
			  "warnings": "Warning: unknown new rules activated (versionbit 28)"
			}
		"#;
        assert_eq!(expected, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_GetRawTransactionResult() {
        let expected = GetRawTransactionResult {
			in_active_chain: None,
			hex: "0200000001586bd02815cf5faabfec986a4e50d25dbee089bd2758621e61c5fab06c334af0000000006b483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2dfeffffff021dc4260c010000001976a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac00e1f505000000001976a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88acfd211500".into(),
			txid: hash!("4a5b5266e1750488395ac15c0376c9d48abf45e4df620777fe8cff096f57aa91"),
			hash: hash!("4a5b5266e1750488395ac15c0376c9d48abf45e4df620777fe8cff096f57aa91"),
			size: 226,
			vsize: 226,
			version: 2,
			locktime: 1384957,
			vin: vec![GetRawTransactionResultVin{
				txid: hash!("f04a336cb0fac5611e625827bd89e0be5dd2504e6a98ecbfaa5fcf1528d06b58"),
				vout: 0,
				script_sig: GetRawTransactionResultVinScriptSig{
					asm: "3045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c[ALL] 03dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2d".into(),
					hex: "483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2d".into(),
				},
				sequence: 4294967294,
				txinwitness: None,

			}],
			vout: vec![GetRawTransactionResultVout{
				value: Amount::from_btc(44.98834461),
				n: 0,
				script_pub_key: GetRawTransactionResultVoutScriptPubKey{
					asm: "OP_DUP OP_HASH160 f602e88b2b5901d8aab15ebe4a97cf92ec6e03b3 OP_EQUALVERIFY OP_CHECKSIG".into(),
					hex: "76a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac".into(),
					req_sigs: 1,
					type_: "pubkeyhash".into(),
					addresses: vec![addr!("n3wk1KcFnVibGdqQa6jbwoR8gbVtRbYM4M")],
				},
			}, GetRawTransactionResultVout{
				value: Amount::from_btc(1.0),
				n: 1,
				script_pub_key: GetRawTransactionResultVoutScriptPubKey{
					asm: "OP_DUP OP_HASH160 687ffeffe8cf4e4c038da46a9b1d37db385a472d OP_EQUALVERIFY OP_CHECKSIG".into(),
					hex: "76a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88ac".into(),
					req_sigs: 1,
					type_: "pubkeyhash".into(),
					addresses: vec![addr!("mq3VuL2K63VKWkp8vvqRiJPre4h9awrHfA")],
				},
			}],
			blockhash: hash!("00000000000000039dc06adbd7666a8d1df9acf9d0329d73651b764167d63765"),
			confirmations: 29446,
			time: 1534935138,
			blocktime: 1534935138,
		};
        let json = r#"
			{
			  "txid": "4a5b5266e1750488395ac15c0376c9d48abf45e4df620777fe8cff096f57aa91",
			  "hash": "4a5b5266e1750488395ac15c0376c9d48abf45e4df620777fe8cff096f57aa91",
			  "version": 2,
			  "size": 226,
			  "vsize": 226,
			  "weight": 904,
			  "locktime": 1384957,
			  "vin": [
				{
				  "txid": "f04a336cb0fac5611e625827bd89e0be5dd2504e6a98ecbfaa5fcf1528d06b58",
				  "vout": 0,
				  "scriptSig": {
					"asm": "3045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c[ALL] 03dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2d",
					"hex": "483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2d"
				  },
				  "sequence": 4294967294
				}
			  ],
			  "vout": [
				{
				  "value": 44.98834461,
				  "n": 0,
				  "scriptPubKey": {
					"asm": "OP_DUP OP_HASH160 f602e88b2b5901d8aab15ebe4a97cf92ec6e03b3 OP_EQUALVERIFY OP_CHECKSIG",
					"hex": "76a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac",
					"reqSigs": 1,
					"type": "pubkeyhash",
					"addresses": [
					  "n3wk1KcFnVibGdqQa6jbwoR8gbVtRbYM4M"
					]
				  }
				},
				{
				  "value": 1.00000000,
				  "n": 1,
				  "scriptPubKey": {
					"asm": "OP_DUP OP_HASH160 687ffeffe8cf4e4c038da46a9b1d37db385a472d OP_EQUALVERIFY OP_CHECKSIG",
					"hex": "76a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88ac",
					"reqSigs": 1,
					"type": "pubkeyhash",
					"addresses": [
					  "mq3VuL2K63VKWkp8vvqRiJPre4h9awrHfA"
					]
				  }
				}
			  ],
			  "hex": "0200000001586bd02815cf5faabfec986a4e50d25dbee089bd2758621e61c5fab06c334af0000000006b483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2dfeffffff021dc4260c010000001976a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac00e1f505000000001976a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88acfd211500",
			  "blockhash": "00000000000000039dc06adbd7666a8d1df9acf9d0329d73651b764167d63765",
			  "confirmations": 29446,
			  "time": 1534935138,
			  "blocktime": 1534935138
			}
		"#;
        assert_eq!(expected, serde_json::from_str(json).unwrap());
        assert!(expected.transaction().is_ok());
        assert_eq!(
            expected.transaction().unwrap().input[0].previous_output.txid,
            hash!("f04a336cb0fac5611e625827bd89e0be5dd2504e6a98ecbfaa5fcf1528d06b58")
        );
        assert!(expected.vin[0].script_sig.script().is_ok());
        assert!(expected.vout[0].script_pub_key.script().is_ok());
    }

    #[test]
    fn test_GetTransactionResult() {
        let expected = GetTransactionResult {
			amount: Amount::from_btc(1.0),
			fee: None,
			confirmations: 30104,
			blockhash: hash!("00000000000000039dc06adbd7666a8d1df9acf9d0329d73651b764167d63765"),
			blockindex: 2028,
			blocktime: 1534935138,
			txid: hash!("4a5b5266e1750488395ac15c0376c9d48abf45e4df620777fe8cff096f57aa91"),
			time: 1534934745,
			timereceived: 1534934745,
			bip125_replaceable: Bip125Replaceable::No,
			details: vec![
				GetTransactionResultDetail {
					address: addr!("mq3VuL2K63VKWkp8vvqRiJPre4h9awrHfA"),
					category: GetTransactionResultDetailCategory::Receive,
					amount: Amount::from_btc(1.0),
					label: "".into(),
					vout: 1,
					fee: None,
					abandoned: None,
				},
			],
			hex: "0200000001586bd02815cf5faabfec986a4e50d25dbee089bd2758621e61c5fab06c334af0000000006b483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2dfeffffff021dc4260c010000001976a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac00e1f505000000001976a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88acfd211500".into(),
		};
        let json = r#"
			{
			  "amount": 1.00000000,
			  "confirmations": 30104,
			  "blockhash": "00000000000000039dc06adbd7666a8d1df9acf9d0329d73651b764167d63765",
			  "blockindex": 2028,
			  "blocktime": 1534935138,
			  "txid": "4a5b5266e1750488395ac15c0376c9d48abf45e4df620777fe8cff096f57aa91",
			  "walletconflicts": [
			  ],
			  "time": 1534934745,
			  "timereceived": 1534934745,
			  "bip125-replaceable": "no",
			  "details": [
				{
				  "address": "mq3VuL2K63VKWkp8vvqRiJPre4h9awrHfA",
				  "category": "receive",
				  "amount": 1.00000000,
				  "label": "",
				  "vout": 1
				}
			  ],
			  "hex": "0200000001586bd02815cf5faabfec986a4e50d25dbee089bd2758621e61c5fab06c334af0000000006b483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2dfeffffff021dc4260c010000001976a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac00e1f505000000001976a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88acfd211500"
			}
		"#;
        assert_eq!(expected, serde_json::from_str(json).unwrap());
        assert!(expected.transaction().is_ok());
    }

    #[test]
    fn test_GetTxOutResult() {
        let expected = GetTxOutResult {
			bestblock: hash!("000000000000002a1fde7234dc2bc016863f3d672af749497eb5c227421e44d5"),
			confirmations: 29505,
			value: Amount::from_btc(1.0),
			script_pub_key: GetRawTransactionResultVoutScriptPubKey{
				asm: "OP_DUP OP_HASH160 687ffeffe8cf4e4c038da46a9b1d37db385a472d OP_EQUALVERIFY OP_CHECKSIG".into(),
				hex: "76a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88ac".into(),
				req_sigs: 1,
				type_: "pubkeyhash".into(),
				addresses: vec![addr!("mq3VuL2K63VKWkp8vvqRiJPre4h9awrHfA")],
			},
			coinbase: false,
		};
        let json = r#"
			{
			  "bestblock": "000000000000002a1fde7234dc2bc016863f3d672af749497eb5c227421e44d5",
			  "confirmations": 29505,
			  "value": 1.00000000,
			  "scriptPubKey": {
				"asm": "OP_DUP OP_HASH160 687ffeffe8cf4e4c038da46a9b1d37db385a472d OP_EQUALVERIFY OP_CHECKSIG",
				"hex": "76a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88ac",
				"reqSigs": 1,
				"type": "pubkeyhash",
				"addresses": [
				  "mq3VuL2K63VKWkp8vvqRiJPre4h9awrHfA"
				]
			  },
			  "coinbase": false
			}
		"#;
        assert_eq!(expected, serde_json::from_str(json).unwrap());
        println!("{:?}", expected.script_pub_key.script());
        assert!(expected.script_pub_key.script().is_ok());
    }

    #[test]
    fn test_ListUnspentResult() {
        let expected = ListUnspentResult {
            txid: hash!("1e66743d6384496fe631501ba3f5b788d4bc193980b847f9e7d4e20d9202489f"),
            vout: 1,
            address: addr!("2N56rvr9bGj862UZMNQhv57nU4GXfMof1Xu"),
            script_pub_key: script!("a914820c9a334a89cb72bc4abfce96efc1fb202cdd9087"),
            amount: Amount::from_btc(2.0),
            confirmations: 29503,
            redeem_script: Some(script!("0014b1a84f7a5c60e58e2c6eee4b33e7585483399af0")),
            spendable: true,
            solvable: true,
            safe: true,
        };
        let json = r#"
			{
			  "txid": "1e66743d6384496fe631501ba3f5b788d4bc193980b847f9e7d4e20d9202489f",
			  "vout": 1,
			  "address": "2N56rvr9bGj862UZMNQhv57nU4GXfMof1Xu",
			  "label": "",
			  "redeemScript": "0014b1a84f7a5c60e58e2c6eee4b33e7585483399af0",
			  "scriptPubKey": "a914820c9a334a89cb72bc4abfce96efc1fb202cdd9087",
			  "amount": 2.00000000,
			  "confirmations": 29503,
			  "spendable": true,
			  "solvable": true,
			  "safe": true
			}
		"#;
        assert_eq!(expected, serde_json::from_str(json).unwrap());
    }

    //TODO(stevenroose) test SignRawTransactionResult

    //TODO(stevenroose) test UTXO

    #[test]
    fn test_deserialize_amount() {
        let vectors = vec![
            ("0", Amount::from_sat(0)),
            ("1", Amount::from_sat(100000000)),
            ("1.00000001", Amount::from_sat(100000001)),
            ("10000000.00000001", Amount::from_sat(1000000000000001)),
        ];
        for vector in vectors.into_iter() {
            let d = deserialize_amount(deserializer!(vector.0)).unwrap();
            assert_eq!(d, vector.1);
        }
    }

    #[test]
    fn test_deserialize_amount_opt() {
        let vectors = vec![
            ("0", Some(Amount::from_sat(0))),
            ("1", Some(Amount::from_sat(100000000))),
            ("1.00000001", Some(Amount::from_sat(100000001))),
            ("10000000.00000001", Some(Amount::from_sat(1000000000000001))),
        ];
        for vector in vectors.into_iter() {
            let d = deserialize_amount_opt(deserializer!(vector.0)).unwrap();
            assert_eq!(d, vector.1);
        }
    }

    #[test]
    fn test_deserialize_difficulty() {
        let vectors = vec![
            ("1.0", 1u64.into()),
            ("0", 0u64.into()),
            ("123.12345", 123u64.into()),
            ("10000000.00000001", 10000000u64.into()),
        ];
        for vector in vectors.into_iter() {
            let d = deserialize_difficulty(deserializer!(vector.0)).unwrap();
            assert_eq!(d, vector.1);
        }
    }

    //#[test]
    //fn test_deserialize_hex() {
    //	let vectors = vec![
    //		(r#""01020304a1ff""#, vec![1,2,3,4,161,255]),
    //		(r#""5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456""#,
    //			sha256d::Hash::from_data(&[]).as_bytes()[..].into()),
    //	];
    //	for vector in vectors.into_iter() {
    //		let d = deserialize_hex(deserializer!(vector.0)).unwrap();
    //		assert_eq!(d, vector.1);
    //	}
    //}

    #[test]
    fn test_deserialize_hex_array_opt() {
        let vectors = vec![(r#"["0102","a1ff"]"#, Some(vec![vec![1, 2], vec![161, 255]]))];
        for vector in vectors.into_iter() {
            let d = deserialize_hex_array_opt(deserializer!(vector.0)).unwrap();
            assert_eq!(d, vector.1);
        }
    }
}
