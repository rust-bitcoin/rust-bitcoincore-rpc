use std::io;
use std::result;

use hex;
use jsonrpc;
use serde_json;

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode as btc_encode;
use bitcoin::util::address::Address;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::privkey::Privkey;
use bitcoin_amount::Amount;
use log::Level::Trace;
use num_bigint::BigUint;
use secp256k1::Signature;
use std::collections::HashMap;

use error::*;
use types::*;

type Result<T> = result::Result<T, Error>;

/// empty quickly creates an empty Vec<serde_json::Value>.
/// Used because using vec![] as default value lacks type annotation.
macro_rules! empty {
	() => {{
		let v: Vec<serde_json::Value> = Vec::new();
			v
		}};
}

macro_rules! result {
	// `json:` converts a JSON response into the provided type.
	($resp:ident, json:$_:tt) => {
		$resp.and_then(|r| r.into_result().map_err(Error::from))
	};

	// `raw:` converts a hex response into a Bitcoin data type.
	// This works both for Option types and regular types.
	($resp:ident, raw:Option<$raw_type:ty>) => {{
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
	($resp:ident, raw:$raw_type:ty) => {
		$resp
			.and_then(|r| r.into_result::<String>().map_err(Error::from))
			.and_then(|h| hex::decode(h).map_err(Error::from))
			.and_then(|r| {
				let t: Result<$raw_type> =
					btc_encode::deserialize(r.as_slice()).map_err(Error::from);
					t
				})
	};
}

/// Main macro used for defining RPC methods.
/// The format used to specify methods is like follows:
/// ```rust
/// #[doc="only works with txindex=1"]
/// pub fn getrawtransaction_raw(self,
/// 	txid: Sha256dHash,
/// 	!false,
/// 	?block_hash: Sha256dHash = ""
/// ) -> raw:Transaction;
/// ```
///
/// It consists out of the following aspects:
/// - Optional meta tags.  Comments can be added using the `#[doc=""]` meta tag.
/// - The method name must be the exact RPC command (i.e. lowercase), optionally followed by an
/// underscore and a suffix (`getrawtransaction` + `_raw`).
/// - There are three types of arguments that must occur in this order:
///   1. normal arguments: appear like normal Rust arguments
///	     e.g. `txid: Sha256dHash`
///   2. fixed value arguments, prefixed with !: These are arguments in the original RPC call,
///      that we don't let the user specify because we need a certain value to be passed.
///      e.g. `!false`
///   3. optional arguments, prefixed with ?: These arguments will occur in the API as Option
///      types, and need to have a default value specified in case it is ommitted.  For the last
///      optional argument, the default value doesn't matter, but still needs to be set, so just
///      set it to `""`.
///      e.g. `?block_hash: Sha256dHash = ""`
/// - The return type is a Rust type prefixed with either `raw:` or `json:` depending on if the
///   type should be decoded with serde (`json:`) or hex + rust-bitcoin consensus decoding `raw:`.
///
/// The eventual method signature of the example above will be:
/// ```rust
/// /// only works with txindex=1
/// pub fn getrawtransaction_raw(&mut self,
/// 	txid: Sha256dHash,
/// 	block_hash: Option<Sha256dHash>,
/// ) -> Result<Transaction>;
/// ```
macro_rules! methods {
	{
		$(
		$(#[$met:meta])*
		pub fn $method:ident(self
			$(, $arg:ident: $argt:ty)*
			$(, !$farg:expr)*
			$(, ?$oarg:ident: $oargt:ty = $oargv:expr)*
		)-> $reskind:ident:$restype:ty;
		)*
	} => {
		$(
		$(#[$met])*
		pub fn $method(
			&mut self
			$(, $arg: $argt)*
			$(, $oarg: Option<$oargt>)*
		) -> Result<$restype> {
			// Split the variant suffix from the method name to get the command.
			//TODO(stevenroose) this should be replaced with an in-macro way to take away the
			// _suffix
			let cmd = stringify!($method).splitn(2, "_").nth(0).unwrap();

			// Build the argument list by combining regular, fixed and optional ones.
			// It just happend to be the case that the fixed-value arguments that we want to set
			// always are in between normal ones and optional ones.  If that changes, we might
			// need to do ugly stuff, but we can avoid that as long as it's not the case.
			let mut args = Vec::new();
			// Normal arguments.
			$( args.push(serde_json::to_value($arg)?); )*
			// Fixed-value arguments.
			$( args.push(serde_json::to_value($farg)?); )*

			// We want to truncate the argument list to remove the trailing non-set optional
			// arguments.  This makes sure we don't send default values if we don't
			// really need to, which prevents unexpected behaviour if the server changes its
			// default values.
			// Because we can't know the last optional arguments before we parsing the macro, we
			// first have to add them to a new vector, and then remove the ones that are not
			// necessary.  Ultimately we can add them to the argument list.
			let mut optional_args = Vec::new();
			$(
				optional_args.push(match $oarg {
					Some(v) => ArgValue::Set(serde_json::to_value(v)?),
					None => ArgValue::Default(serde_json::to_value($oargv)?),
				});
			)*
			while let Some(ArgValue::Default(_)) = optional_args.last() {
				optional_args.pop();
			}
			args.extend(optional_args.into_iter().map(|a| match a {
				ArgValue::Set(v) => v,
				ArgValue::Default(v) => v,
			}));

			let req = self.client.build_request(cmd.to_owned(), args);
			if log_enabled!(Trace) {
				trace!("JSON-RPC request: {}", serde_json::to_string(&req).unwrap());
			}

			let resp = self.client.send_request(&req).map_err(Error::from);
			if log_enabled!(Trace) && resp.is_ok() {
				let resp = resp.as_ref().unwrap();
				trace!("JSON-RPC response: {}", serde_json::to_string(resp).unwrap());
			}

			result!(resp, $reskind:$restype)
		}
		)*
	};
}

/// ArgValue is a simple enum to represent an argument value and its context.
enum ArgValue {
	Set(serde_json::Value),
	Default(serde_json::Value),
}

impl ArgValue {
	fn val(self) -> serde_json::Value {
		match self {
			ArgValue::Set(v) => v,
			ArgValue::Default(v) => v,
		}
	}
}

/// Create an ArgValue::Set.
fn arg<T>(value: T) -> Result<ArgValue>
where
	T: serde::ser::Serialize,
{
	Ok(ArgValue::Set(serde_json::to_value(value)?))
}

/// Create an ArgValue from an optional argument, using the default value when the value is None.
fn oarg<T, D>(value: Option<T>, default: D) -> Result<ArgValue>
where
	T: serde::ser::Serialize,
	D: serde::ser::Serialize,
{
	match value {
		Some(val) => Ok(ArgValue::Set(serde_json::to_value(val)?)),
		None => Ok(ArgValue::Default(serde_json::to_value(default)?)),
	}
}

/// Read the response body as hex and decode into a rust-bitcoin struct.
fn into_struct<T>(resp: jsonrpc::Response) -> Result<T>
where
	T: bitcoin::consensus::Decodable<std::io::Cursor<Vec<u8>>>,
{
	let hex = resp.into_result::<String>()?;
	let bytes = hex::decode(hex)?;
	Ok(T::consensus_decode(&mut io::Cursor::new(bytes))?)
}

/// Read the response body as JSON and decode into a JSON type..
fn into_json<T>(resp: jsonrpc::Response) -> Result<T>
where
	T: for<'a> serde::de::Deserialize<'a>,
{
	Ok(resp.into_result()?)
}

/// Client implements a JSON-RPC client for the Bitcoin Core daemon or compatible APIs.
///
/// Methods have identical casing to API methods on purpose.
/// Variants of API methods are formed using an underscore.
pub struct Client {
	client: jsonrpc::client::Client,
}

impl Client {
	/// Create a new Client.
	pub fn new(client: jsonrpc::client::Client) -> Client {
		Client {
			client: client,
		}
	}

	fn call(&mut self, cmd: &str, mut args: Vec<ArgValue>) -> Result<jsonrpc::Response> {
		// We want to truncate the argument list to remove the trailing non-set optional
		// arguments.  This makes sure we don't send default values if we don't
		// really need to, which prevents unexpected behaviour if the server changes its
		// default values.
		// Because we can't know the last optional arguments before we parsing the macro, we
		// first have to add them to a new vector, and then remove the ones that are not
		// necessary.  Ultimately we can add them to the argument list.
		while let Some(ArgValue::Default(_)) = args.last() {
			args.pop();
		}

		let json_args = args.into_iter().map(|v| v.val()).collect();
		let req = self.client.build_request(cmd.to_owned(), json_args);
		if log_enabled!(Trace) {
			trace!("JSON-RPC request: {}", serde_json::to_string(&req).unwrap());
		}

		let resp = self.client.send_request(&req).map_err(Error::from);
		if log_enabled!(Trace) && resp.is_ok() {
			let resp = resp.as_ref().unwrap();
			trace!("JSON-RPC response: {}", serde_json::to_string(resp).unwrap());
		}
		resp
	}

	pub fn addmultisigaddress(
		&mut self,
		nrequired: usize,
		keys: Vec<PubKeyOrAddress>,
		label: Option<&str>,
		address_type: Option<AddressType>,
	) -> Result<AddMultiSigAddressResult> {
		let resp = self.call(
			"addmultisigaddress",
			vec![arg(nrequired)?, arg(keys)?, oarg(label, "")?, oarg(address_type, "")?],
		)?;
		into_json(resp)
	}

	methods! {
		//pub fn addmultisigaddress(self,
		//	nrequired: usize,
		//	keys: Vec<PubKeyOrAddress>,
		//	?label: &str = "",
		//	?address_type: AddressType = ""
		//) -> json:AddMultiSigAddressResult;

		pub fn backupwallet(self, ?destination: &str = "") -> json:();

		//TODO(stevenroose) use Privkey type
		pub fn dumpprivkey(self, address: Address) -> json:String;

		pub fn encryptwallet(self, passphrase: String) -> json:();

		pub fn getblock_raw(self, hash: Sha256dHash, !0) -> raw:Block;

		pub fn getblock_info(self, hash: Sha256dHash, !1) -> json:GetBlockResult;
		//TODO(stevenroose) add getblock_txs

		pub fn getblockcount(self) -> json:usize;

		pub fn getblockhash(self, height: u32) -> json:Sha256dHash;

		pub fn getblockheader_raw(self, hash: Sha256dHash, !false) -> raw:BlockHeader;

		pub fn getblockheader_verbose(self, hash: Sha256dHash, !true) -> json:GetBlockHeaderResult;

		//TODO(stevenroose) verify if return type works
		pub fn getdifficulty(self) -> json:BigUint;

		pub fn getconnectioncount(self) -> json:usize;

		pub fn getmininginfo(self) -> json:GetMiningInfoResult;
	}

	pub fn getrawtransaction(
		&mut self,
		txid: Sha256dHash,
		block_hash: Option<Sha256dHash>,
	) -> Result<Transaction> {
		let resp =
			self.call("getrawtransaction", vec![arg(txid)?, arg(true)?, oarg(block_hash, "")?])?;
		into_struct(resp)
	}

	methods!{
		//pub fn getrawtransaction(self,
		//	txid: Sha256dHash,
		//	!false,
		//	?block_hash: Sha256dHash = ""
		//) -> raw:Transaction;

		pub fn getrawtransaction_verbose(self,
			txid: Sha256dHash,
			!true,
			?block_hash: Sha256dHash = ""
		) -> json:GetRawTransactionResult;

		pub fn getreceivedbyaddress(self, address: Address, ?minconf: u32 = 0) -> json:Amount;

		pub fn gettransaction(self,
			txid: Sha256dHash,
			?include_watchonly: bool = true
		) -> json:GetTransactionResult;

		pub fn gettxout(self,
			txid: Sha256dHash,
			vout: u32,
			?include_mempool: bool = true
		) -> json:Option<GetTxOutResult>;

		//TODO(stevenroose) use Privkey type
		// dep: https://github.com/rust-bitcoin/rust-bitcoin/pull/183
		pub fn importprivkey(self,
			privkey: &str,
			?label: &str = "",
			?rescan: bool = true
		) -> json:();

		pub fn keypoolrefill(self, ?new_size: usize = 0) -> json:();

		pub fn listunspent(self,
			?minconf: usize = 0,
			?maxconf: usize = 9999999,
			?addresses: Vec<Address> = empty!(),
			?include_unsafe: bool = true,
			?query_options: HashMap<String, String> = ""
		) -> json:Vec<ListUnspentResult>;

		//TODO(stevenroose) update with privkey type
		// dep: https://github.com/rust-bitcoin/rust-bitcoin/pull/183
		#[doc="private_keys are not yet implemented."]
		pub fn signrawtransaction(self,
			tx: HexBytes,
			?utxos: Vec<UTXO> = empty!(),
			?private_keys: Vec<String> = empty!(),
			?sighash_type: SigHashType = ""
		) -> json:SignRawTransactionResult;

		pub fn signrawtransactionwithwallet(self,
			tx: HexBytes,
			?utxos: Vec<UTXO> = empty!(),
			?sighash_type: SigHashType = ""
		) -> json:SignRawTransactionResult;

		pub fn stop(self) -> json:();

		pub fn verifymessage(self,
			address: Address,
			signature: Signature,
			message: &str
		) -> json:bool;
	}
}
