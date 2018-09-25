//! # Rust Client for Bitcoin Core API
//!
//! This is a client library for the Bitcoin Core JSON-RPC API.
//!

#![crate_name = "bitcoindrpc"]
#![crate_type = "rlib"]

#[macro_use]
extern crate serde_derive;
extern crate bitcoin;
extern crate bitcoin_amount;
extern crate hex;
extern crate jsonrpc;
extern crate num_bigint;
extern crate serde;
extern crate serde_json;

use std::collections::HashMap;

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{Transaction, SigHashType};
use bitcoin::network::encodable::ConsensusDecodable;
use bitcoin::network::serialize::{RawDecoder};
use bitcoin::util::address::Address;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::privkey::Privkey;
use bitcoin_amount::Amount;
use num_bigint::BigUint;
use serde::de::Error as SerdeError;
use serde::Deserialize;

mod error;

pub use error::Error;


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

/// A JSON-RPC client for the Bitcoin Core daemon or compatible APIs.
pub struct Client {
	client: jsonrpc::client::Client,
}

enum Arg {
	Required(serde_json::Value),
	OptionalSet(serde_json::Value),
	OptionalDefault(serde_json::Value),
}

macro_rules! arg {
	($val:expr) => {
		Arg::Required(serde_json::to_value($val)?)
	};
	($val:expr, $def:expr) => {
		match $val {
			Some(v) => Arg::OptionalSet(serde_json::to_value(v)?),
			None => Arg::OptionalDefault(serde_json::to_value($def)?),
		}
	};
	($val:expr,) => { arg!($val, "") };
}

macro_rules! empty {
	() => { { let v: Vec<serde_json::Value> = vec![]; v } }
}

macro_rules! make_call {
	($self:ident, $method:expr) => { make_call!($self, $method,) };
	($self:ident, $method:expr, $($arg:expr),*) => {
		{
			// We want to truncate the argument to remove the trailing non-set optional arguments.
			// This makes sure we don't send default values if we don't really need to and this 
			// can prevent unexpected behaviour if the server changes its default values.
			let mut args = Vec::new();
			$( args.push($arg); )*
			while let Some(Arg::OptionalDefault(_)) = args.last() {
				args.pop();
			}
			let json_args = args.into_iter().map(|a| match a {
				Arg::Required(v) => v,
				Arg::OptionalSet(v) => v,
				Arg::OptionalDefault(v) => v,
			}).collect();
			let req = $self.client.build_request($method.to_string(), json_args);
			$self.client.send_request(&req).map_err(Error::from)
		}
	}
}

/// Convert a response object into the provided type.
macro_rules! result_json {
	($resp:ident, $json_type:ty) => {
		$resp.and_then(|r| r.into_result::<$json_type>().map_err(Error::from))
	}
}

macro_rules! result_raw {
	($resp:ident, Option<$raw_type:ty>) => {
		{
			let hex_opt = $resp.and_then(|r| r.into_result::<Option<String>>()
					.map_err(Error::from))?;
			match hex_opt {
				Some(hex) => {
					let raw = hex::decode(hex)?;
					match <$raw_type>::consensus_decode(&mut RawDecoder::new(raw.as_slice())) {
						Ok(val) => Ok(Some(val)),
						Err(e) => Err(e.into()),
					}
				},
				None => Ok(None),
			}
		}
	};
	($resp:ident, $raw_type:ty) => {
		$resp.and_then(|r| r.into_result::<String>().map_err(Error::from))
			 .and_then(|h| hex::decode(h).map_err(Error::from))
			 .and_then(|r| <$raw_type>::consensus_decode(&mut RawDecoder::new(r.as_slice()))
					.map_err(Error::from))
	};
}

impl Client {
	pub fn new(uri: String, user: Option<String>, pass: Option<String>) -> Client {
		Client {
			client: jsonrpc::client::Client::new(uri, user, pass),
		}
	}

	// Methods have identical casing to API methods on purpose.
	// Variants of API methods are formed using an underscore.

	pub fn getblock_raw(&mut self, hash: Sha256dHash) -> Result<Block, Error> {
		let resp = make_call!(self, "getblock", arg!(hash), arg!(0));
		result_raw!(resp, Block)
	}

	pub fn getblock_info(&mut self, hash: Sha256dHash) -> Result<GetBlockResult, Error> {
		let resp = make_call!(self, "getblock", arg!(hash), arg!(1));
		result_json!(resp, GetBlockResult)
	}
	//TODO(stevenroose) getblock_raw (should be serialized to
	// bitcoin::blockdata::Block) and getblock_txs

	pub fn getblockcount(&mut self) -> Result<usize, Error> {
		let resp = make_call!(self, "getblockcount");
		result_json!(resp, usize)
	}

	pub fn getblockhash(&mut self, height: u32) -> Result<Sha256dHash, Error> {
		let resp = make_call!(self, "getblockhash", arg!(height));
		result_json!(resp, Sha256dHash)
	}

	pub fn getblockheader(&mut self, hash: Sha256dHash) -> Result<BlockHeader, Error> {
		let resp = make_call!(self, "getblockheader", arg!(hash), arg!(true));
		result_raw!(resp, BlockHeader)
	}

	pub fn getblockheader_verbose(&mut self, hash: Sha256dHash) -> Result<GetBlockHeaderResult, Error> {
		let resp = make_call!(self, "getblockheader", arg!(hash), arg!(true));
		result_json!(resp, GetBlockHeaderResult)
	}

	pub fn getrawtransaction(
		&mut self,
		txid: Sha256dHash,
		block_hash: Option<Sha256dHash>,
	) -> Result<Option<Transaction>, Error> {
		let resp = make_call!(self, "getrawtransaction", arg!(txid), arg!(false), arg!(block_hash));
		result_raw!(resp, Option<Transaction>)
	}

	pub fn getrawtransaction_verbose(
		&mut self,
		txid: Sha256dHash,
		block_hash: Option<Sha256dHash>,
	) -> Result<Option<GetRawTransactionResult>, Error> {
		let resp = make_call!(self, "getrawtransaction", arg!(txid), arg!(true), arg!(block_hash));
		result_json!(resp, Option<GetRawTransactionResult>)
	}

	pub fn gettxout(
		&mut self,
		txid: Sha256dHash,
		vout: u32,
		include_mempool: Option<bool>,
	) -> Result<Option<GetTxOutResult>, Error> {
		let resp = make_call!(self, "gettxout", arg!(txid), arg!(vout), arg!(include_mempool,));
		result_json!(resp, Option<GetTxOutResult>)
	}

	pub fn listunspent(
		&mut self,
		minconf: Option<usize>,
		maxconf: Option<usize>,
		addresses: Option<Vec<Address>>,
		include_unsafe: Option<bool>,
		query_options: Option<HashMap<String, String>>,
	) -> Result<Vec<ListUnspentResult>, Error> {
		let resp = make_call!(self, "listunspent", arg!(minconf, 0), arg!(maxconf, 9999999),
			arg!(addresses, empty!()), arg!(include_unsafe, true), arg!(query_options,));
		result_json!(resp, Vec<ListUnspentResult>)
	}

	pub fn signrawtransaction(
		&mut self,
		tx: &[u8],
		utxos: Option<Vec<UTXO>>,
		private_keys: Option<Vec<Vec<u8>>>,
		sighash_type: Option<SigHashType>,
	) -> Result<SignRawTransactionResult, Error> {
		let sighash = sighash_string(sighash_type);
		let resp = make_call!(self, "signrawtransaction", arg!(hex::encode(tx)),
			arg!(utxos, empty!()), arg!(Some(empty!()), empty!()),//TODO(stevenroose) impl privkeys
			arg!(sighash,));
		result_json!(resp, SignRawTransactionResult)
	}
}

/// Convert a SigHashType object to a string representation used in the API.
fn sighash_string(sighash: Option<SigHashType>) -> Option<String> {
	match sighash {
		None => None,
		Some(sh) => Some(String::from(match sh {
			SigHashType::All => "ALL",
			SigHashType::None => "NONE",
			SigHashType::Single => "SINGLE",
			SigHashType::AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
			SigHashType::NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
			SigHashType::SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
		})),
	}
}

/// Deserializes a BTC-denominated floating point Bitcoin amount into the Amount
/// type.
fn deserialize_amount<'de, D>(deserializer: D) -> Result<Amount, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let btc = f64::deserialize(deserializer)?;
	Ok(Amount::from_btc(btc))
}

/// Deserializes a hex-encoded byte array.
fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let h = String::deserialize(deserializer)?;
	hex::decode(h).map_err(D::Error::custom)
}

/// Deserializes a vector of hex-encoded byte arrays.
fn deserialize_hex_array_opt<'de, D>(deserializer: D) -> Result<Option<Vec<Vec<u8>>>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	// Revisit when issue is fixed:
	// https://github.com/serde-rs/serde/issues/723
	
	let v: Vec<String> = Vec::deserialize(deserializer)?;
	let mut res = Vec::new();
	for h in v.into_iter() {
		res.push(hex::decode(h).map_err(D::Error::custom)?);
	}
	Ok(Some(res))
}
