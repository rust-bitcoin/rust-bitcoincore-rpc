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
extern crate strason;

use std::collections::HashMap;
use std::error;
use std::fmt;

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::SigHashType;
use bitcoin::util::address::Address;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::privkey::Privkey;
use bitcoin_amount::Amount;
use num_bigint::BigUint;
use serde::de::Error as SerdeError;
use serde::ser::Serialize;
use serde::Deserialize;

/// The error type for errors produced in this library.
#[derive(Debug)]
pub enum Error {
	JsonRpc(jsonrpc::error::Error),
	FromHex(hex::FromHexError),
	Strason(strason::Error),
}

impl From<jsonrpc::error::Error> for Error {
	fn from(e: jsonrpc::error::Error) -> Error {
		Error::JsonRpc(e)
	}
}

impl From<hex::FromHexError> for Error {
	fn from(e: hex::FromHexError) -> Error {
		Error::FromHex(e)
	}
}

impl From<strason::Error> for Error {
	fn from(e: strason::Error) -> Error {
		Error::Strason(e)
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Error::JsonRpc(ref e) => write!(f, "JSON-RPC error: {}", e),
			Error::FromHex(ref e) => write!(f, "hex decode error: {}", e),
			Error::Strason(ref e) => write!(f, "JSON error: {}", e),
		}
	}
}

impl error::Error for Error {
	fn description(&self) -> &str {
		match *self {
			Error::JsonRpc(_) => "JSON-RPC error",
			Error::FromHex(_) => "hex decode error",
			Error::Strason(_) => "JSON error",
		}
	}

	fn cause(&self) -> Option<&error::Error> {
		match *self {
			Error::JsonRpc(ref e) => Some(e),
			Error::FromHex(ref e) => Some(e),
			Error::Strason(ref e) => Some(e),
		}
	}
}

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
pub struct GetTxOutResultScriptPubKey {
	pub asm: String,
	#[serde(deserialize_with = "deserialize_hex")]
	pub hex: Vec<u8>,
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
	pub script_pub_key: GetTxOutResultScriptPubKey,
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

impl Client {
	pub fn new(uri: String, user: Option<String>, pass: Option<String>) -> Client {
		Client {
			client: jsonrpc::client::Client::new(uri, user, pass),
		}
	}

	// Methods have identical casing to API methods on purpose.
	// Variants of API methods are formed using an underscore.

	pub fn getblock_info(&mut self, hash: Sha256dHash) -> Result<GetBlockResult, Error> {
		let args: Vec<strason::Json> = vec![hash.to_string().into(), 1.into()];
		let req = self.client.build_request("getblock".to_string(), args);
		self.client
			.send_request(&req)
			.and_then(|res| res.into_result::<GetBlockResult>())
			.map_err(Error::from)
	}
	//TODO(stevenroose) getblock_raw (should be serialized to
	// bitcoin::blockdata::Block) and getblock_txs

	pub fn getblockcount(&mut self) -> Result<usize, Error> {
		let req = self
			.client
			.build_request("getblockclount".to_string(), vec![]);
		self.client
			.send_request(&req)
			.and_then(|res| res.into_result::<usize>())
			.map_err(Error::from)
	}

	pub fn gettxout(
		&mut self,
		txid: Sha256dHash,
		vout: u32,
		include_mempool: Option<bool>,
	) -> Result<GetTxOutResult, Error> {
		let mut args: Vec<strason::Json> = vec![txid.to_string().into(), vout.into()];
		if let Some(b) = include_mempool {
			args.push(b.into());
		}

		let req = self.client.build_request("gettxout".to_string(), args);
		self.client
			.send_request(&req)
			.and_then(|res| res.into_result::<GetTxOutResult>())
			.map_err(Error::from)
			.into()
	}

	pub fn listunspent(
		&mut self,
		minconf: Option<usize>,
		maxconf: Option<usize>,
		addresses: Option<Vec<Address>>,
		include_unsafe: Option<bool>,
		query_options: Option<HashMap<String, String>>,
	) -> Result<Vec<ListUnspentResult>, Error> {
		// Only provide the minimum required arguments. Provide defaults if
		// later arguments are provided.
		let mut args: Vec<strason::Json> = Vec::new();
		if let Some(min) = minconf {
			args.push(min.into());
		} else if maxconf != None
			|| addresses != None
			|| include_unsafe != None
			|| query_options != None
		{
			args.push(0.into());
		}

		if let Some(max) = maxconf {
			args.push(max.into());
		} else if addresses != None || include_unsafe != None || query_options != None {
			args.push(9999999.into());
		}

		if let Some(addr) = addresses {
			let mut addrs: Vec<strason::Json> = vec![];
			for a in addr.iter() {
				addrs.push(a.to_string().into());
			}
			args.push(addrs.into());
		} else if include_unsafe != None || query_options != None {
			let v: Vec<strason::Json> = vec![];
			args.push(v.into());
		}

		if let Some(inc) = include_unsafe {
			args.push(inc.into());
		} else if query_options != None {
			args.push(true.into());
		}

		if let Some(opts) = query_options {
			args.push(strason::Json::from_serialize(opts)?);
		}

		let req = self.client.build_request("listunspent".to_string(), args);
		self.client
			.send_request(&req)
			.and_then(|res| res.into_result::<Vec<ListUnspentResult>>())
			.map_err(Error::from)
			.into()
	}

	pub fn signrawtransaction(
		&mut self,
		tx: &[u8],
		utxos: Option<Vec<UTXO>>,
		private_keys: Option<Vec<Vec<u8>>>,
		sighash_type: Option<SigHashType>,
	) -> Result<SignRawTransactionResult, Error> {
		let mut args: Vec<strason::Json> = Vec::new();
		args.push(hex::encode(tx).into());

		if let Some(utxos_val) = utxos {
			let mut utxos_json: Vec<strason::Json> = vec![];
			for u in utxos_val.iter() {
				utxos_json.push(strason::Json::from_serialize(u)?);
			}
			args.push(utxos_json.into());
		} else if private_keys != None || sighash_type != None {
			args.push("".into())
		}

		if let Some(privkeys) = private_keys {
			//TODO(stevenroose) encode private keys to WIF
			args.push("".into())
		} else if sighash_type != None {
			args.push("".into())
		}

		if let Some(sighash) = sighash_type {
			args.push(sighash_string(sighash).into());
		}

		let req = self
			.client
			.build_request("signrawtransaction".to_string(), args);
		self.client
			.send_request(&req)
			.and_then(|res| res.into_result::<SignRawTransactionResult>())
			.map_err(Error::from)
			.into()
	}
}

/// Convert a SigHashType object to a string representation used in the API.
fn sighash_string(sighash: SigHashType) -> String {
	String::from(match sighash {
		SigHashType::All => "ALL",
		SigHashType::None => "NONE",
		SigHashType::Single => "SINGLE",
		SigHashType::AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
		SigHashType::NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
		SigHashType::SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
	})
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
