
use hex;
use serde;

use bitcoin::blockdata::script::Script;
use bitcoin::util::address::Address;
use bitcoin::util::hash::Sha256dHash;
use bitcoin_amount::Amount;
use num_bigint::BigUint;
use serde::de::Error as SerdeError;
use serde::Deserialize;


#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockResult {
	pub hash: Sha256dHash,
	pub confirmations: usize,
	pub size: usize,
	pub strippedsize: Option<usize>,
	pub weight: usize,
	pub height: usize,
	pub version: u32,
	pub version_hex: Option<String>,
	pub merkleroot: Sha256dHash,
	pub tx: Vec<Sha256dHash>,
	pub time: usize,
	pub mediantime: Option<usize>,
	pub nonce: u32,
	pub bits: String,
	pub difficulty: BigUint,
	pub chainwork: String,
	pub n_tx: usize,
	pub previousblockhash: Option<Sha256dHash>,
	pub nextblockhash: Option<Sha256dHash>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResult {
	pub hash: Sha256dHash,
	pub confirmations: usize,
	pub height: usize,
	pub version: u32,
	pub version_hex: Option<String>,
	pub merkleroot: Sha256dHash,
	pub time: usize,
	pub mediantime: Option<usize>,
	pub nonce: u32,
	pub bits: String,
	pub difficulty: BigUint,
	pub chainwork: String,
	pub n_tx: usize,
	pub previousblockhash: Option<Sha256dHash>,
	pub nextblockhash: Option<Sha256dHash>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVinScriptSig {
	pub asm: String,
	pub hex: Script,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVin {
	pub txid: Sha256dHash,
	pub vout: u32,
	pub script_sig: GetRawTransactionResultVinScriptSig,
	pub sequence: u32,
	#[serde(default)]
	#[serde(deserialize_with = "deserialize_hex_array_opt")]
	pub txinwitness: Option<Vec<Vec<u8>>>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVoutScriptPubKey {
	pub asm: String,
	pub hex: Script,
	pub req_sigs: usize,
	#[serde(rename = "type")]
	pub type_: String, //TODO(stevenroose) consider enum
	pub addresses: Vec<Address>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVout {
	#[serde(deserialize_with = "deserialize_amount")]
	pub value: Amount,
	pub n: u32,
	pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResult {
	#[serde(rename = "in_active_chain")]
	pub in_active_chain: Option<bool>,
	#[serde(deserialize_with = "deserialize_hex")]
	pub hex: Vec<u8>,
	pub txid: Sha256dHash,
	pub hash: Sha256dHash,
	pub size: usize,
	pub vsize: usize,
	pub version: u32,
	pub locktime: u32,
	pub vin: Vec<GetRawTransactionResultVin>,
	pub vout: Vec<GetRawTransactionResultVout>,
	pub blockhash: Sha256dHash,
	pub confirmations: usize,
	pub time: usize,
	pub blocktime: usize,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultScriptPubKey {
	pub asm: String,
	pub hex: Script,
	pub req_sigs: usize,
	#[serde(rename = "type")]
	pub type_: String, //TODO(stevenroose) consider enum
	pub addresses: Vec<Address>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetTxOutResult {
	pub bestblock: Sha256dHash,
	pub confirmations: usize,
	#[serde(deserialize_with = "deserialize_amount")]
	pub value: Amount,
	pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
	pub coinbase: bool,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentResult {
	pub txid: Sha256dHash,
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

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionResultError {
	pub txid: Sha256dHash,
	pub vout: u32,
	pub script_sig: Script,
	pub sequence: u32,
	pub error: String,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionResult {
	#[serde(deserialize_with = "deserialize_hex")]
	pub hex: Vec<u8>,
	pub complete: bool,
	#[serde(default)]
	pub errors: Vec<SignRawTransactionResultError>,
}

// Custom types for input arguments.

// Used for signrawtransaction argument.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UTXO {
	pub txid: Sha256dHash,
	pub vout: u32,
	pub script_pub_key: Script,
	pub redeem_script: Script,
}

/// deserialize_amount deserializes a BTC-denominated floating point Bitcoin amount into the 
/// Amount type.
fn deserialize_amount<'de, D>(deserializer: D) -> Result<Amount, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let btc = f64::deserialize(deserializer)?;
	Ok(Amount::from_btc(btc))
}

/// deserialize_hex deserializes a hex-encoded byte array.
fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let h = String::deserialize(deserializer)?;
	hex::decode(h).map_err(D::Error::custom)
}

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
