use std::io;
use std::result;

use hex;
use jsonrpc;
use serde_json;

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::consensus::encode as btc_encode;
use bitcoin::util::address::Address;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::Transaction;
//use bitcoin::util::privkey::Privkey;
use bitcoin_amount::Amount;
use log::Level::Trace;
use num_bigint::BigUint;
use secp256k1::Signature;
use std::collections::HashMap;

use error::*;
use json;

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

/// Read the response body as hex and decode into a rust-bitcoin struct.
fn hex_consensus_decode<T>(hex: &str) -> Result<T>
where
    T: bitcoin::consensus::Decodable<std::io::Cursor<Vec<u8>>>,
{
    let bytes = hex::decode(hex)?;
    Ok(T::consensus_decode(&mut io::Cursor::new(bytes))?)
}

/// A type that can be used as an id when querying for `Querable`
// TODO: Unnecessary? Always `Sha256dHash`? --dpc
pub trait Id {
    fn to_json_value(&self) -> serde_json::value::Value;
}

impl Id for Sha256dHash {
    fn to_json_value(&self) -> serde_json::value::Value {
        self.to_string().into()
    }
}

/// A type that can be queried from the Node
pub trait Querable: Sized {
    /// Type of the id used to query the item
    type Id: Id;
    /// Query the item using `rpc` and convert to `Self`
    fn query(rpc: &mut Client, id: &Self::Id) -> Result<Self>;
}

impl Querable for bitcoin::blockdata::block::Block {
    type Id = Sha256dHash;

    fn query(rpc: &mut Client, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getblock";
        let hex: String = rpc.call(rpc_name, &[id.to_json_value(), 0.into()])?;
        let bytes = bitcoin::util::misc::hex_bytes(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }
}

impl Querable for bitcoin::blockdata::transaction::Transaction {
    type Id = Sha256dHash;

    fn query(rpc: &mut Client, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getrawtransaction";
        let hex: String = rpc.call(rpc_name, &[id.to_json_value()])?;
        let bytes = bitcoin::util::misc::hex_bytes(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }
}
/// Shorthand for converting a variable into a serde_json::Value.
fn into_json<T>(val: T) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    Ok(serde_json::to_value(val)?)
}

/// Shorthand for converting an Option into an Option<serde_json::Value>.
fn opt_into_json<T>(opt: Option<T>) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => Ok(into_json(val)?),
        None => Ok(serde_json::Value::Null),
    }
}

/// Shorthand for `serde_json::Value::Null`.
#[allow(unused)]
fn null() -> serde_json::Value {
    serde_json::Value::Null
}

/// Handle default values in the argument list
///
/// Substitute `Value::Null`s with corresponding values from `defaults` table,
/// except when they are trailing, in which case just skip them altogether
/// in returned list.
///
/// Note, that `defaults` corresponds to the last elements of `args`.
///
/// ```norust
/// arg1 arg2 arg3 arg4
///           def1 def2
/// ```
///
/// Elements of `args` without corresponding `defaults` value, won't
/// be substituted, because they are required.
fn handle_defaults<'a, 'b>(
    args: &'a mut [serde_json::Value],
    defaults: &'b [serde_json::Value],
) -> &'a [serde_json::Value] {
    assert!(args.len() >= defaults.len());

    // Pass over the optional arguments in backwards order, filling in defaults after the first
    // non-null optional argument has been observed.
    let mut first_non_null_optional_idx = None;
    for i in 0..defaults.len() {
        let args_i = args.len() - 1 - i;
        let defaults_i = defaults.len() - 1 - i;
        if args[args_i] == serde_json::Value::Null {
            if first_non_null_optional_idx.is_some() {
                args[args_i] = defaults[defaults_i].clone();
            }
        } else {
            if first_non_null_optional_idx.is_none() {
                first_non_null_optional_idx = Some(args_i);
            }
        }
    }

    let required_num = args.len() - defaults.len();

    if let Some(i) = first_non_null_optional_idx {
        &args[..=i]
    } else {
        &args[..required_num]
    }
}

// TODO: move to a test module
#[test]
fn test_handle_defaults() -> Result<()> {
    {
        let mut args = [into_json(0)?, null(), null()];
        let defaults = [into_json(1)?, into_json(2)?];
        let res = [into_json(0)?];
        assert_eq!(handle_defaults(&mut args, &defaults), &res);
    }
    {
        let mut args = [into_json(0)?, into_json(1)?, null()];
        let defaults = [into_json(2)?];
        let res = [into_json(0)?, into_json(1)?];
        assert_eq!(handle_defaults(&mut args, &defaults), &res);
    }
    {
        let mut args = [into_json(0)?, null(), into_json(5)?];
        let defaults = [into_json(2)?, into_json(3)?];
        let res = [into_json(0)?, into_json(2)?, into_json(5)?];
        assert_eq!(handle_defaults(&mut args, &defaults), &res);
    }
    {
        let mut args = [into_json(0)?, null(), into_json(5)?, null()];
        let defaults = [into_json(2)?, into_json(3)?, into_json(4)?];
        let res = [into_json(0)?, into_json(2)?, into_json(5)?];
        assert_eq!(handle_defaults(&mut args, &defaults), &res);
    }
    {
        let mut args = [null(), null()];
        let defaults = [into_json(2)?, into_json(3)?];
        let res: [serde_json::Value; 0] = [];
        assert_eq!(handle_defaults(&mut args, &defaults), &res);
    }
    {
        let mut args = [];
        let defaults = [];
        let res: [serde_json::Value; 0] = [];
        assert_eq!(handle_defaults(&mut args, &defaults), &res);
    }
    {
        let mut args = [into_json(0)?];
        let defaults = [into_json(2)?];
        let res = [into_json(0)?];
        assert_eq!(handle_defaults(&mut args, &defaults), &res);
    }
    Ok(())
}

/// Client implements a JSON-RPC client for the Bitcoin Core daemon or compatible APIs.
///
/// Methods have identical casing to API methods on purpose.
/// Variants of API methods are formed using an underscore.
pub struct Client {
    client: jsonrpc::client::Client,
}

impl Client {
    /// Creates a client to a bitcoind JSON-RPC server.
    pub fn new(url: String, user: Option<String>, pass: Option<String>) -> Self {
        debug_assert!(pass.is_none() || user.is_some());

        Client {
            client: jsonrpc::client::Client::new(url, user, pass),
        }
    }

    /// Create a new Client.
    pub fn from_jsonrpc(client: jsonrpc::client::Client) -> Client {
        Client {
            client: client,
        }
    }

    /// Query an object implementing `Querable` type
    pub fn get_by_id<T: Querable>(&mut self, id: &<T as Querable>::Id) -> Result<T> {
        T::query(self, &id)
    }

    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &mut self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        // Get rid of to_owned after
        // https://github.com/apoelstra/rust-jsonrpc/pull/19
        // lands
        let req = self.client.build_request(cmd.to_owned(), args.to_owned());
        if log_enabled!(Trace) {
            trace!("JSON-RPC request: {}", serde_json::to_string(&req).unwrap());
        }

        let resp = self.client.send_request(&req).map_err(Error::from);
        if log_enabled!(Trace) && resp.is_ok() {
            let resp = resp.as_ref().unwrap();
            trace!("JSON-RPC response: {}", serde_json::to_string(resp).unwrap());
        }
        Ok(resp?.into_result()?)
    }

    pub fn addmultisigaddress(
        &mut self,
        nrequired: usize,
        keys: Vec<json::PubKeyOrAddress>,
        label: Option<&str>,
        address_type: Option<json::AddressType>,
    ) -> Result<json::AddMultiSigAddressResult> {
        let mut args = [
            into_json(nrequired)?,
            into_json(keys)?,
            opt_into_json(label)?,
            opt_into_json(address_type)?,
        ];
        self.call("addmultisigaddress", handle_defaults(&mut args, &[]))
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

        pub fn getblock_info(self, hash: Sha256dHash, !1) -> json:json::GetBlockResult;
        //TODO(stevenroose) add getblock_txs

        pub fn getblockheader_raw(self, hash: Sha256dHash, !false) -> raw:BlockHeader;

        pub fn getblockheader_verbose(self, hash: Sha256dHash, !true) -> json:json::GetBlockHeaderResult;

        //TODO(stevenroose) verify if return type works
        pub fn getdifficulty(self) -> json:BigUint;

        pub fn getconnectioncount(self) -> json:usize;

        pub fn getmininginfo(self) -> json:json::GetMiningInfoResult;
    }

    /// Returns a data structure containing various state info regarding
    /// blockchain processing.
    pub fn getblockchaininfo(&mut self) -> Result<json::BlockchainInfo> {
        self.call("getblockchaininfo", &[])
    }

    /// Returns the numbers of block in the longest chain.
    pub fn getblockcount(&mut self) -> Result<u64> {
        self.call("getblockcount", &[])
    }

    /// Returns the hash of the best (tip) block in the longest blockchain.
    pub fn getbestblockhash(&mut self) -> Result<Sha256dHash> {
        let hex: String = self.call("getbestblockhash", &[])?;
        Ok(Sha256dHash::from_hex(&hex)?)
    }

    /// Get block hash at a given height
    pub fn getblockhash(&mut self, height: u64) -> Result<Sha256dHash> {
        let hex: String = self.call("getblockhash", &[height.into()])?;
        Ok(Sha256dHash::from_hex(&hex)?)
    }

    pub fn getrawtransaction(
        &mut self,
        txid: Sha256dHash,
        block_hash: Option<Sha256dHash>,
    ) -> Result<Transaction> {
        let mut args = [into_json(txid)?, opt_into_json(block_hash)?];
        let resp: String = self.call("getrawtransaction", handle_defaults(&mut args, &[]))?;
        hex_consensus_decode(&resp)
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
        ) -> json:json::GetRawTransactionResult;

        pub fn getreceivedbyaddress(self, address: Address, ?minconf: u32 = 0) -> json:Amount;

        pub fn gettransaction(self,
            txid: Sha256dHash,
            ?include_watchonly: bool = true
        ) -> json:json::GetTransactionResult;

        pub fn gettxout(self,
            txid: Sha256dHash,
            vout: u32,
            ?include_mempool: bool = true
        ) -> json:Option<json::GetTxOutResult>;

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
        ) -> json:Vec<json::ListUnspentResult>;

        //TODO(stevenroose) update with privkey type
        // dep: https://github.com/rust-bitcoin/rust-bitcoin/pull/183
        #[doc="private_keys are not yet implemented."]
        pub fn signrawtransaction(self,
            tx: json::HexBytes,
            ?utxos: Vec<json::UTXO> = empty!(),
            ?private_keys: Vec<String> = empty!(),
            ?sighash_type: json::SigHashType = ""
        ) -> json:json::SignRawTransactionResult;

        pub fn signrawtransactionwithwallet(self,
            tx: json::HexBytes,
            ?utxos: Vec<json::UTXO> = empty!(),
            ?sighash_type: json::SigHashType = ""
        ) -> json:json::SignRawTransactionResult;

        pub fn stop(self) -> json:();

        pub fn verifymessage(self,
            address: Address,
            signature: Signature,
            message: &str
        ) -> json:bool;
    }
}
