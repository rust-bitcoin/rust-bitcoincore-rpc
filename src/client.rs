use std::result;

use hex;
use jsonrpc;
use serde_json;

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::transaction::{SigHashType, Transaction};
use bitcoin::consensus::encode as btc_encode;
use bitcoin::util::address::Address;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::privkey::Privkey;
use bitcoin_amount::Amount;
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
				let t: Result<$raw_type> =
					btc_encode::deserialize(r.as_slice()).map_err(Error::from);
					t
				})
	};
}

/// This macro generated methods that corresponds to RPC calls.  Because of the issue with fixed
/// arguments, this macro is only used for methods that return JSON-parsed return types.
/// The parameters in order are:
/// - the method name
/// - (optional) the command name in case it's not the same as the method name
/// - the return type prefixed by `json:` or `raw:` for json-parsed or consensus-decoded types
/// - (optional) a list of required params and their type
/// a semicolon is used to seperate ^ and v
/// - (optional) a list of optional params, their type and their default value (use "" for none)
/// - (optional) a fixed-value param to place in between required and optional params
macro_rules! call {
	// Actual expansions used internally.
	(@int $method:ident, $cmd:ident, json:$res:ty, $($arg:ident: $argt:ty),*; 
	 $($oarg:ident: $oargt:ty: $oargv:expr),*; $($fix:expr),*) => {
		pub fn $method(&mut self $(, $arg: $argt)* $(, $oarg: Option<$oargt>)*) -> Result<$res> {
			let resp = make_call!(self, stringify!($cmd)
								  $(, arg!($arg))* $(, arg!($fix))* $(, arg!($oarg, $oargv))*);
			result_json!(resp)
		}
	};
	(@int $method:ident, $cmd:ident, raw:$res:ty, $($arg:ident: $argt:ty),*; 
	 $($oarg:ident: $oargt:ty: $oargv:expr),*; $($fix:expr),*) => {
		pub fn $method(&mut self $(, $arg: $argt)* $(, $oarg: Option<$oargt>)*) -> Result<$res> {
			let resp = make_call!(self, stringify!($cmd)
								  $(, arg!($arg))* $(, arg!($fix))* $(, arg!($oarg, $oargv))*);
			result_raw!(resp, $res)
		}
	};

	// Rust method is JSON-RPC command suffixed with a variant name.
	//
	// Since it's not possible to join two ident captures with an underscore, in the case of a
	// method variant, the method name needs to be repeated in full instead of just the suffix.
	// This could be fixed somehow when the "mashup" crate becomes std lib or when
	// concat_idents! gets fixed to be used inside macros.
	($method:ident, $cmd:ident, $rt:ident:$res:ty $(, $arg:ident: $argt:ty)*; 
	 $($oarg:ident: $oargt:ty: $oargv:expr),*; $fixed:expr) => {
		call!(@int $method, $cmd, $rt:$res, $($arg: $argt),*; $($oarg: $oargt: $oargv),*; $fixed);
	};
	($method:ident, $cmd:ident, $rt:ident:$res:ty $(,$arg:ident: $argt:ty)*; 
	 $($oarg:ident: $oargt:ty: $oargv:expr),*) => {
		call!(@int $method, $cmd, $rt:$res, $($arg: $argt),*; $($oarg: $oargt),*;);
	};
	($method:ident, $cmd:ident, $rt:ident:$res:ty $(,$arg:ident: $argt:ty)*) => {
		call!(@int $method, $cmd, $rt:$res, $($arg: $argt),*;;);
	};

	// Rust method is same as JSON-RPC command.
	($cmd:ident, $rt:ident:$res:ty $(, $arg:ident: $argt:ty)*; 
	 $($oarg:ident: $oargt:ty: $oargv:expr),*; $fixed:expr) => {
		call!(@int $cmd, $cmd, $rt:$res, $($arg: $argt),*; $($oarg: $oargt: $oargv),*; $fixed);
	};
	($cmd:ident, $rt:ident:$res:ty $(, $arg:ident: $argt:ty)*; 
	 $($oarg:ident: $oargt:ty: $oargv:expr),*) => {
		call!(@int $cmd, $cmd, $rt:$res, $($arg: $argt),*; $($oarg: $oargt: $oargv),*;);
	};
	($cmd:ident, $rt:ident:$res:ty $(, $arg:ident: $argt:ty)*) => {
		call!(@int $cmd, $cmd, $rt:$res, $($arg: $argt),*;;);
	};
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

	call!(addmultisigaddress, json:AddMultiSigAddressResult, nrequired: usize, 
		  keys: Vec<PubKeyOrAddress>; label: &str: "", address_type: AddressType: "");

	call!(backupwallet, json:(), destination: &str);

	//TODO(stevenroose) use Privkey type
	call!(dumpprivkey, json:String, address: Address);

	call!(encryptwallet, json:(), passphrase: &str);

	call!(getblock_raw, getblock, raw:Block, hash: Sha256dHash; ; 0);

	call!(getblock_info, getblock, json:GetBlockResult, hash: Sha256dHash; ; 1);
	//TODO(stevenroose) add getblock_txs

	call!(getblockcount, json:usize);

	call!(getblockhash, json:Sha256dHash, height: u32);

	call!(getblockheader, raw:BlockHeader, hash: Sha256dHash; ; false);

	call!(getblockheader_verbose, getblockheader, json:GetBlockHeaderResult, 
		  hash: Sha256dHash; ; true);
	
	//TODO(stevenroose) verify if return type works
	call!(getdifficulty, json:BigUint);

	call!(getconnectioncount, json:usize);

	call!(getmininginfo, json:GetMiningInfoResult);

	call!(getrawtransaction, raw:Transaction, txid: Sha256dHash; 
		  block_hash: Sha256dHash: ""; false);

	call!(getrawtransaction_verbose, getrawtransaction, json:GetRawTransactionResult,
		  txid: Sha256dHash; block_hash: Sha256dHash: ""; true);

	call!(getreceivedbyaddress, json:Amount, address: Address; minconf: u32: 0);

	call!(gettransaction, json:GetTransactionResult, 
		  txid: Sha256dHash; include_watchonly: bool: true);

	call!(gettxout, json:GetTxOutResult, 
		  txid: Sha256dHash, vout: u32; include_mempool: bool: true);

	//TODO(stevenroose) use Privkey type
	call!(importprivkey, json:(), privkey: &str; label: &str: "", rescan: bool: true);

	call!(keypoolrefill, json:(); new_size: usize: 0);

	call!(listunspent, json:Vec<ListUnspentResult>; minconf: usize: 0, maxconf: usize: 9999999,
			   addresses: Vec<Address>: empty!(), include_unsafe: bool: true,
			   query_options: HashMap<String, String>: "");

	//TODO(stevenroose) macro the hex thing
	/// private_keys are not yet implemented.
	pub fn signrawtransaction(
		&mut self,
		tx: &[u8],
		utxos: Option<Vec<UTXO>>,
		private_keys: Option<Vec<Vec<u8>>>,
		sighash_type: Option<SigHashType>,
	) -> Result<SignRawTransactionResult> {
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
	) -> Result<SignRawTransactionResult> {
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

	call!(stop, json:());

	call!(verifymessage, json:bool, address: Address, signature: Signature, message: &str);
}

//TODO(stevenroose) consider porting this to rust-bitcoin with serde::Serialize
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
