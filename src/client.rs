use hex;
use jsonrpc;
use serde;
use serde_json;

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::transaction::{SigHashType, Transaction};
use bitcoin::consensus::encode as btc_encode;
use bitcoin::util::address::Address;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::privkey::Privkey;
use bitcoin_amount::Amount;
use num_bigint::BigUint;
use secp256k1::{PublicKey, Secp256k1, Signature};
use std::collections::HashMap;

use error::*;
use types::*;

/// Arg is a simple enum to represent an argument value and its context.
enum Arg {
	Required(serde_json::Value),
	OptionalSet(serde_json::Value),
	OptionalDefault(serde_json::Value),
}

/// arg is used to quickly generate Arg instances.  For optional argument a default value can be
/// provided that will be used if the actual value was None.  If the default value doesn't matter
/// (f.e. for the last optional argument), it can be left empty, but a comma should still be
/// present.
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
	($val:expr,) => {
		arg!($val, "")
	};
}

/// empty quickly creates an empty Vec<serde_json::Value>.
/// Used because using vec![] as default value lacks type annotation.
macro_rules! empty {
	() => {{
		let v: Vec<serde_json::Value> = vec![];
			v
		}};
}

/// make_call processes the argument list and makes the RPC call to the server.
/// It returns the response object.
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

/// result_json converts a JSON response into the provided type.
macro_rules! result_json {
	($resp:ident) => {
		$resp.and_then(|r| r.into_result().map_err(Error::from))
	};
}

/// result_raw converts a hex response into a Bitcoin data type.
/// This works both for Option types and regular types.
macro_rules! result_raw {
	($resp:ident, Option<$raw_type:ty>) => {{
		let hex_opt = $resp.and_then(|r| r.into_result::<Option<String>>().map_err(Error::from))?;
		match hex_opt {
			Some(hex) => {
				let raw = hex::decode(hex)?;
				match btc_encode::deserialize(raw.as_slice()) {
					Ok(val) => Ok(Some(val)),
					Err(e) => Err(e.into()),
				}
				}
			None => Ok(None),
			}
		}};
	($resp:ident, $raw_type:ty) => {
		$resp
			.and_then(|r| r.into_result::<String>().map_err(Error::from))
			.and_then(|h| hex::decode(h).map_err(Error::from))
			.and_then(|r| {
				let t: Result<$raw_type, Error> =
					btc_encode::deserialize(r.as_slice()).map_err(Error::from);
					t
				})
	};
}

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
		serializer.serialize_str(match self {
			AddressType::Legacy => "legacy",
			AddressType::P2shSegwit => "p2sh-segwit",
			AddressType::Bech32 => "bech32",
		})
	}
}

/// Used to represent arguments that can either be an address or a public key.
pub enum PubKeyOrAddress {
	Address(Address),
	PubKey(PublicKey),
}

impl serde::Serialize for PubKeyOrAddress {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		match self {
			PubKeyOrAddress::Address(a) => serde::Serialize::serialize(a, serializer),
			PubKeyOrAddress::PubKey(k) => serde::Serialize::serialize(k, serializer),
		}
	}
}

/// Client implements a JSON-RPC client for the Bitcoin Core daemon or compatible APIs.
pub struct Client {
	client: jsonrpc::client::Client,
}

impl Client {
	/// Create a new Client.
	///
	/// Methods have identical casing to API methods on purpose.
	/// Variants of API methods are formed using an underscore.
	pub fn new(uri: String, user: Option<String>, pass: Option<String>) -> Client {
		Client {
			client: jsonrpc::client::Client::new(uri, user, pass),
		}
	}

	pub fn addmultisigaddress(
		&mut self,
		nrequired: usize,
		keys: Vec<PubKeyOrAddress>,
		label: Option<String>,
		address_type: Option<AddressType>,
	) -> Result<AddMultiSigAddressResult, Error> {
		let resp = make_call!(
			self,
			"addmultisigaddress",
			arg!(nrequired),
			arg!(keys),
			arg!(label,),
			arg!(address_type,)
		);
		result_json!(resp)
	}

	pub fn backupwallet(&mut self, destination: String) -> Result<(), Error> {
		let resp = make_call!(self, "backupwallet", arg!(destination));
		result_json!(resp)
	}

	//TODO(stevenroose) use Privkey type
	pub fn dumpprivkey(&mut self, address: Address) -> Result<String, Error> {
		let resp = make_call!(self, "dumpprivkey", arg!(address));
		result_json!(resp)
	}

	pub fn encryptwallet(&mut self, passphrase: String) -> Result<(), Error> {
		let resp = make_call!(self, "encryptwallet", arg!(passphrase));
		result_json!(resp)
	}

	pub fn getblock_raw(&mut self, hash: Sha256dHash) -> Result<Block, Error> {
		let resp = make_call!(self, "getblock", arg!(hash), arg!(0));
		result_raw!(resp, Block)
	}

	pub fn getblock_info(&mut self, hash: Sha256dHash) -> Result<GetBlockResult, Error> {
		let resp = make_call!(self, "getblock", arg!(hash), arg!(1));
		result_json!(resp)
	}
	//TODO(stevenroose) add getblock_txs

	pub fn getblockcount(&mut self) -> Result<usize, Error> {
		let resp = make_call!(self, "getblockcount");
		result_json!(resp)
	}

	pub fn getblockhash(&mut self, height: u32) -> Result<Sha256dHash, Error> {
		let resp = make_call!(self, "getblockhash", arg!(height));
		result_json!(resp)
	}

	pub fn getblockheader(&mut self, hash: Sha256dHash) -> Result<BlockHeader, Error> {
		let resp = make_call!(self, "getblockheader", arg!(hash), arg!(true));
		result_raw!(resp, BlockHeader)
	}

	pub fn getblockheader_verbose(
		&mut self,
		hash: Sha256dHash,
	) -> Result<GetBlockHeaderResult, Error> {
		let resp = make_call!(self, "getblockheader", arg!(hash), arg!(true));
		result_json!(resp)
	}

	//TODO(stevenroose) verify if return type works
	pub fn getdifficulty(&mut self) -> Result<BigUint, Error> {
		let resp = make_call!(self, "getdifficulty");
		result_json!(resp)
	}

	pub fn getconnectioncount(&mut self) -> Result<usize, Error> {
		let resp = make_call!(self, "getconnectioncount");
		result_json!(resp)
	}

	pub fn getmininginfo(&mut self) -> Result<GetMiningInfoResult, Error> {
		let resp = make_call!(self, "getmininginfo");
		result_json!(resp)
	}

	pub fn getrawtransaction(
		&mut self,
		txid: Sha256dHash,
		block_hash: Option<Sha256dHash>,
	) -> Result<Option<Transaction>, Error> {
		let resp = make_call!(
			self,
			"getrawtransaction",
			arg!(txid),
			arg!(false),
			arg!(block_hash)
		);
		result_raw!(resp, Option<Transaction>)
	}

	pub fn getrawtransaction_verbose(
		&mut self,
		txid: Sha256dHash,
		block_hash: Option<Sha256dHash>,
	) -> Result<GetRawTransactionResult, Error> {
		let resp = make_call!(
			self,
			"getrawtransaction",
			arg!(txid),
			arg!(true),
			arg!(block_hash)
		);
		result_json!(resp)
	}

	pub fn getreceivedbyaddress(
		&mut self,
		address: Address,
		minconf: Option<u32>,
	) -> Result<Amount, Error> {
		let resp = make_call!(self, "getreceivedbyaddress", arg!(address), arg!(minconf,));
		result_json!(resp)
	}

	pub fn gettransaction(
		&mut self,
		txid: Sha256dHash,
		include_watchonly: Option<bool>,
	) -> Result<GetTransactionResult, Error> {
		let resp = make_call!(self, "gettransaction", arg!(txid), arg!(include_watchonly,));
		result_json!(resp)
	}

	pub fn gettxout(
		&mut self,
		txid: Sha256dHash,
		vout: u32,
		include_mempool: Option<bool>,
	) -> Result<Option<GetTxOutResult>, Error> {
		let resp = make_call!(
			self,
			"gettxout",
			arg!(txid),
			arg!(vout),
			arg!(include_mempool,)
		);
		result_json!(resp)
	}

	//TODO(stevenroose) use Privkey type
	pub fn importprivkey(&mut self, privkey: String, label: Option<String>, rescan: Option<bool>) -> Result<(), Error> {
		let resp = make_call!(self, "importprivkey", arg!(privkey), arg!(label,), arg!(rescan,));
		result_json!(resp)
	}

	pub fn keypoolrefill(&mut self, new_size: Option<usize>) -> Result<(), Error> {
		let resp = make_call!(self, "keypoolrefill", arg!(new_size,));
		result_json!(resp)
	}

	pub fn listunspent(
		&mut self,
		minconf: Option<usize>,
		maxconf: Option<usize>,
		addresses: Option<Vec<Address>>,
		include_unsafe: Option<bool>,
		query_options: Option<HashMap<String, String>>,
	) -> Result<Vec<ListUnspentResult>, Error> {
		let resp = make_call!(
			self,
			"listunspent",
			arg!(minconf, 0),
			arg!(maxconf, 9999999),
			arg!(addresses, empty!()),
			arg!(include_unsafe, true),
			arg!(query_options,)
		);
		result_json!(resp)
	}

	/// private_keys are not yet implemented.
	pub fn signrawtransaction(
		&mut self,
		tx: &[u8],
		utxos: Option<Vec<UTXO>>,
		private_keys: Option<Vec<Vec<u8>>>,
		sighash_type: Option<SigHashType>,
	) -> Result<SignRawTransactionResult, Error> {
		if private_keys.is_some() {
			unimplemented!();
		}
		let sighash = sighash_string(sighash_type);
		let resp = make_call!(
			self,
			"signrawtransaction",
			arg!(hex::encode(tx)),
			arg!(utxos, empty!()),
			arg!(Some(empty!()), empty!()), //TODO(stevenroose) impl privkeys
			arg!(sighash,)
		);
		result_json!(resp)
	}

	/// private_keys are not yet implemented.
	pub fn signrawtransactionwithwallet(
		&mut self,
		tx: &[u8],
		utxos: Option<Vec<UTXO>>,
		sighash_type: Option<SigHashType>,
	) -> Result<SignRawTransactionResult, Error> {
		let sighash = sighash_string(sighash_type);
		let resp = make_call!(
			self,
			"signrawtransactionwithwallet",
			arg!(hex::encode(tx)),
			arg!(utxos, empty!()),
			arg!(sighash,)
		);
		result_json!(resp)
	}

	pub fn stop(&mut self) -> Result<(), Error> {
		let resp = make_call!(self, "stop");
		result_json!(resp)
	}

	pub fn verifymessage(
		&mut self,
		address: Address,
		signature: Signature,
		message: &str,
	) -> Result<bool, Error> {
		let secp = Secp256k1::without_caps();
		let resp = make_call!(
			self,
			"verifymessage",
			arg!(address),
			arg!(hex::encode(signature.serialize_der(&secp))),
			arg!(message)
		);
		result_json!(resp)
	}
}

/// sighash_string converts a SigHashType object to a string representation used in the API.
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
