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
			if log_enabled!(Trace) {
				trace!("JSON-RPC request: {}", serde_json::to_string(&req).unwrap());
			}
			let resp = $self.client.send_request(&req).map_err(Error::from);
			if log_enabled!(Trace) && resp.is_ok() {
				let resp = resp.as_ref().unwrap();
				trace!("JSON-RPC response: {}", serde_json::to_string(resp).unwrap());
			}
			resp
		}
	}
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

macro_rules! methods {
	{
		$(
		pub fn $method:ident(self
			$(, $arg:ident: $argt:ty)*
			$(, !$farg:expr)*
			$(, ?$oarg:ident: $oargt:ty = $oargv:expr)*
		)-> $reskind:ident:$restype:ty;
		)*
	} => {
		$(
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
			$( args.push(Arg::Required(serde_json::to_value($arg)?)); )*
			// Fixed-value arguments.
			$( args.push(Arg::Required(serde_json::to_value($farg)?)); )*
			// Optional arguments.
			$( args.push(match $oarg {
				Some(v) => Arg::OptionalSet(serde_json::to_value(v)?),
				None => Arg::OptionalDefault(serde_json::to_value($oargv)?),
			   });
			)*

			// We want to truncate the argument list to remove the trailing non-set optional
			// arguments.
			// This makes sure we don't send default values if we don't really need to, which
			// prevents unexpected behaviour if the server changes its default values.
			while let Some(Arg::OptionalDefault(_)) = args.last() {
				args.pop();
			}

			let json_args = args.into_iter().map(|a| match a {
				Arg::Required(v) => v,
				Arg::OptionalSet(v) => v,
				Arg::OptionalDefault(v) => v,
			}).collect();

			let req = self.client.build_request(cmd.to_owned(), json_args);
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

	//call!(backupwallet, json:(), destination: &str);
	methods! {
		pub fn addmultisigaddress(self,
			nrequired: usize,
			keys: Vec<PubKeyOrAddress>,
			?label: &str = "",
			?address_type: AddressType = ""
		) -> json:AddMultiSigAddressResult;

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

		pub fn getrawtransaction_raw(self,
			txid: Sha256dHash,
			!false,
			?block_hash: Sha256dHash = ""
		) -> raw:Transaction;

		pub fn getrawtransaction_verbose(self,
			txid: Sha256dHash,
			!false,
			?block_hash: Sha256dHash = ""
		) -> raw:Transaction;

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
	}

	//TODO(stevenroose) macro the hex thing
	/// private_keys are not yet implemented.
	pub fn signrawtransaction(
		&mut self,
		tx: HexBytes,
		utxos: Option<Vec<UTXO>>,
		private_keys: Option<Vec<Vec<u8>>>,
		sighash_type: Option<SigHashType>,
	) -> Result<SignRawTransactionResult> {
		if private_keys.is_some() {
			unimplemented!();
		}
		let resp = make_call!(
			self,
			"signrawtransaction",
			arg!(tx),
			arg!(utxos, empty!()),
			arg!(Some(empty!()), empty!()), //TODO(stevenroose) impl privkeys
			arg!(sighash_type,)
		);
		resp.and_then(|r| r.into_result().map_err(Error::from))
	}

	/// private_keys are not yet implemented.
	pub fn signrawtransactionwithwallet(
		&mut self,
		tx: HexBytes,
		utxos: Option<Vec<UTXO>>,
		sighash_type: Option<SigHashType>,
	) -> Result<SignRawTransactionResult> {
		let resp = make_call!(
			self,
			"signrawtransactionwithwallet",
			arg!(tx),
			arg!(utxos, empty!()),
			arg!(sighash_type,)
		);
		resp.and_then(|r| r.into_result().map_err(Error::from))
	}

	methods!{
		pub fn stop(self) -> json:();

		pub fn verifymessage(self,
			address: Address,
			signature: Signature,
			message: &str
		) -> json:bool;
	}
}
