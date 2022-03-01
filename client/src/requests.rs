
use std::str::FromStr;

use jsonrpc::client::Request;//, Batch};
use jsonrpc::client::{ConverterError, List, Param, Params};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::bitcoin::hashes::hex::{HexIterator, FromHex};
use crate::bitcoin::secp256k1::ecdsa::Signature;
use crate::bitcoin::{
    self, Address, Amount, Block, PrivateKey, PublicKey, ScriptBuf, Transaction,
};
use crate::bitcoin::block::Header as BlockHeader;
use crate::bitcoin::psbt::PartiallySignedTransaction;
type UncheckedAddress = Address<crate::bitcoin::address::NetworkUnchecked>;

use crate::serialize::{
    HexListSerializeWrapper, HexSerializeWrapper,
    OutPointListObjectSerializeWrapper,
    StringListSerializeWrapper, StringSerializeWrapper,
};
use crate::{json, AddressParam, BlockRef, BlockParam, Error, PsbtParam, SighashParam, TxParam};

fn converter_hex<T>(raw: Box<RawValue>) -> Result<T, ConverterError>
where
    T: bitcoin::consensus::encode::Decodable,
{
    let hex: &str = serde_json::from_str(raw.get())?;
    let mut bytes = HexIterator::new(hex)?;
    Ok(T::consensus_decode(&mut bytes)?)
}

fn converter_raw_hex(raw: Box<RawValue>) -> Result<Vec<u8>, ConverterError> {
    let hex: &str = serde_json::from_str(raw.get())?;
    Ok(Vec::<u8>::from_hex(&hex)?)
}

pub(crate) fn converter_json<T>(raw: Box<RawValue>) -> Result<T, ConverterError>
where 
    T: serde::de::DeserializeOwned,
{
    Ok(serde_json::from_str(raw.get())?)
}

fn converter_btc(raw: Box<RawValue>) -> Result<Amount, ConverterError> {
    let btc = serde_json::from_str::<f64>(raw.get())?;
    Ok(Amount::from_btc(btc)?)
}

fn converter_psbt(raw: Box<RawValue>) -> Result<PartiallySignedTransaction, ConverterError> {
    let b64 = serde_json::from_str::<&str>(raw.get())?;
    Ok(PartiallySignedTransaction::from_str(b64)?)
}

/// Converter for calls that expect an empty result and a string indicates an error.
fn converter_expect_null(raw: Box<RawValue>) -> Result<(), ConverterError> {
    match serde_json::from_str::<serde_json::Value>(raw.get()) {
        Ok(serde_json::Value::Null) => Ok(()),
        Ok(res) => Err(Error::ReturnedError(res.to_string()).into()),
        Err(err) => Err(err.into()),
    }
}

// The following methods are shorthands to create [Param] objects.

trait IntoJsonValue {
    fn into_value(&self) -> serde_json::Value;
}

macro_rules! into_json_from {
    ($t:ty) => {
        impl IntoJsonValue for $t {
            fn into_value(&self) -> serde_json::Value {
                serde_json::Value::from(*self)
            }
        }
    };
}
into_json_from!(bool);
into_json_from!(usize);
into_json_from!(u16);
into_json_from!(u32);
into_json_from!(u64);
into_json_from!(i32);
into_json_from!(i64);
into_json_from!(f64);

/// Convert a basic type into a value parameter.
#[inline]
fn v<T: IntoJsonValue>(v: T) -> Param<'static> {
    Param::Value(v.into_value())
}

/// Same as [v], but for options.
#[inline]
fn ov<T: IntoJsonValue>(o: Option<T>) -> Option<Param<'static>> {
    o.map(v)
}

/// Allocate the given variable on the heap into a boxed parameter.
#[inline]
fn b<T>(v: T) -> Param<'static> where T: serde::Serialize + Sync + 'static {
    Param::InBox(Box::new(v))
}

/// Same as [b] but for options.
#[allow(unused)]
#[inline]
fn ob<T>(o: Option<T>) -> Option<Param<'static>> where T: serde::Serialize + Sync + 'static {
    o.map(b)
}

/// Convert a reference into a reference parameter.
#[inline]
fn r<'a, T>(p: &'a T) -> Param<'a> where T: serde::Serialize + Sync {
    Param::ByRef(p)
}

/// Same as for [r] but for options.
#[inline]
fn or<'a, T>(o: Option<&'a T>) -> Option<Param<'a>> where T: serde::Serialize + Sync {
    o.map(r)
}

/// Create a boxed pre-allocated boxed parameter.
#[inline]
fn raw<T>(v: T) -> Param<'static> where T: serde::Serialize {
    let serialized = serde_json::to_string(&v).expect("serializer shoudln't fail");
    let raw = serde_json::value::RawValue::from_string(serialized).expect("valid utf8");
    Param::Raw(raw)
}

/// Macro to generate a Params value.
///
/// Params are passed as either a regular (key, value) tuple,
/// or as a ?-prefixed tuple where the value is an Option.
/// The optional parameters must always succeed the non-optional ones.
///
/// Example:
/// params![ ("key", value), ?("key", Some(value)) ]
macro_rules! params {
    () => {{ Params::ByName(List::Slice(&[])) }};
    // Special case for only optional ones.
    ($(?($k2:expr, $v2:expr)),* $(,)?) => ( params![, $( ?($k2, $v2), )* ] );
    ($(($k1:expr, $v1:expr)),*, $(?($k2:expr, $v2:expr)),* $(,)?) => {{
        let mut n = 0;
        $( let _ = $k1; n += 1; )*
        // For optional params we could check if $v2 is some,
        // but currently $v2 is an expression and we don't want to 
        // evaluate it twice. It's not too bad like this.
        $( let _ = $k2; n += 1; )*
        //TODO(stevenroose) use smallvec
        let mut ret = Vec::<(&str, Param)>::with_capacity(n);
        $(
            ret.push(($k1, $v1));
        )*
        $(
            if let Some(v) = $v2 {
                ret.push(($k2, v));
            }
        )*
        Params::from(ret)
    }};
}

// *************
// * MAIN PART *
// *************

#[inline(always)]
pub fn get_network_info() -> Request<'static, json::GetNetworkInfoResult> {
    Request {
        method: "getnetworkinfo".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn version() -> Request<'static, usize> {
    Request {
        method: "getnetworkinfo".into(),
        params: params![],
        converter: &|raw| {
            #[derive(Deserialize)]
            struct Response {
                pub version: usize,
            }
            let ret = serde_json::from_str::<Response>(raw.get())?;
            Ok(ret.version)
        },
    }
}

#[inline(always)]
pub fn get_index_info() -> Request<'static, json::GetIndexInfoResult> {
    Request {
        method: "getindexinfo".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn add_multisig_address<'r>(
    nrequired: usize,
    keys: &'r &'r [json::PubKeyOrAddress],
    label: Option<&'r &'r str>,
    address_type: Option<&'r json::AddressType>,
) -> Request<'r, json::AddMultiSigAddressResult> {
    Request {
        method: "addmultisigaddress".into(),
        params: params![
            ("nrequired", v(nrequired)),
            ("keys", r(keys)),
            ?("label", or(label)),
            ?("address_type", or(address_type)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn load_wallet<'r>(wallet: &'r &'r str) -> Request<'r, json::LoadWalletResult> {
    Request {
        method: "loadwallet".into(),
        params: params![
            ("filename", r(wallet)),
            //TODO(stevenroose) missing param
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn unload_wallet<'r>(wallet: Option<&'r &'r str>) -> Request<'r, json::UnloadWalletResult> {
    Request {
        method: "unloadwallet".into(),
        params: params![
            ?("wallet_name", or(wallet)),
            //TODO(stevenroose) missing param
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn create_wallet<'r>(
    wallet: &'r &'r str,
    disable_private_keys: Option<bool>,
    blank: Option<bool>,
    passphrase: Option<&'r &'r str>,
    avoid_reuse: Option<bool>,
) -> Request<'r, json::LoadWalletResult> {
    Request {
        method: "createwallet".into(),
        params: params![
            ("wallet_name", r(wallet)),
            ?("disable_private_keys", ov(disable_private_keys)),
            ?("blank", ov(blank)),
            ?("passphrase", or(passphrase)),
            ?("avoid_reuse", ov(avoid_reuse)),
            //TODO(stevenroose) missing params
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn list_wallets() -> Request<'static, Vec<String>> {
    Request {
        method: "listwallets".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn list_wallet_dir() -> Request<'static, Vec<String>> {
    Request {
        method: "listwalletdir".into(),
        params: params![],
        converter: &|raw| {
            let ret: json::ListWalletDirResult = converter_json(raw)?;
            Ok(ret.wallets.into_iter().map(|x| x.name).collect())
        },
    }
}

#[inline(always)]
pub fn get_wallet_info() -> Request<'static, json::GetWalletInfoResult> {
    Request {
        method: "getwalletinfo".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn backup_wallet<'r>(destination: &'r &'r str) -> Request<'r, ()> {
    Request {
        method: "backupwallet".into(),
        params: params![
            ("destination", r(destination)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn dump_private_key<'r>(
    address: &'r StringSerializeWrapper<'r, impl AddressParam + ?Sized>,
) -> Request<'r, PrivateKey> {
    Request {
        method: "dumpprivkey".into(),
        params: params![
            ("address", r(address)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn encrypt_wallet<'r>(passphrase: &'r &'r str) -> Request<'r, String> {
    Request {
        method: "encryptwallet".into(),
        params: params![
            ("passphrase", r(passphrase)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_difficulty() -> Request<'static, f64> {
    Request {
        method: "getdifficulty".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_connection_count() -> Request<'static, usize> {
    Request {
        method: "getconnectioncount".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_block<'r>(hash: &'r bitcoin::BlockHash) -> Request<'r, Block> {
    Request {
        method: "getblock".into(),
        params: params![
            ("blockhash", r(hash)),
            ("verbose", v(0)),
        ],
        converter: &|raw| converter_hex(raw),
    }
}

#[inline(always)]
pub fn get_block_hex<'r>(hash: &'r bitcoin::BlockHash) -> Request<'r, String> {
    Request {
        method: "getblock".into(),
        params: params![
            ("blockhash", r(hash)),
            ("verbose", v(0)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_block_info<'r>(hash: &'r bitcoin::BlockHash) -> Request<'r, json::GetBlockResult> {
    Request {
        method: "getblock".into(),
        params: params![
            ("blockhash", r(hash)),
            ("verbose", v(1)),
        ],
        converter: &|raw| converter_json(raw),
    }
}
//TODO(stevenroose) add getblock_txs

#[inline(always)]
pub fn get_block_header<'r>(hash: &'r bitcoin::BlockHash) -> Request<'r, BlockHeader> {
    Request {
        method: "getblockheader".into(),
        params: params![
            ("blockhash", r(hash)),
            ("verbose", v(false)),
        ],
        converter: &|raw| converter_hex(raw),
    }
}

#[inline(always)]
pub fn get_block_header_info<'r>(
    hash: &'r bitcoin::BlockHash,
) -> Request<'r, json::GetBlockHeaderResult> {
    Request {
        method: "getblockheader".into(),
        params: params![
            ("blockhash", r(hash)),
            ("verbose", v(true)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_mining_info() -> Request<'static, json::GetMiningInfoResult> {
    Request {
        method: "getmininginfo".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_block_template<'r>(
    mode: &'r json::GetBlockTemplateModes,
    rules: &'r &'r [json::GetBlockTemplateRules],
    capabilities: &'r &'r [json::GetBlockTemplateCapabilities],
) -> Request<'r, json::GetBlockTemplateResult> {
    #[derive(Serialize)]
    struct Argument<'a> {
        mode: &'a json::GetBlockTemplateModes,
        rules: &'a [json::GetBlockTemplateRules],
        capabilities: &'a [json::GetBlockTemplateCapabilities],
    }

    Request {
        method: "getblocktemplate".into(),
        params: params![
            ("template_request", raw(Argument {
                mode: mode,
                rules: rules,
                capabilities: capabilities,
            })),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_blockchain_info() -> Request<'static, json::GetBlockchainInfoResult> {
    Request {
        method: "getblockchaininfo".into(),
        params: params![],
        converter: &|raw| {
            use Error::UnexpectedStructure as err;

            let mut raw = serde_json::from_str::<serde_json::Value>(raw.get())?;

            // The softfork fields are not backwards compatible:
            // - 0.18.x returns a "softforks" array and a "bip9_softforks" map.
            // - 0.19.x returns a "softforks" map.
            let is_legacy = {
                let obj = raw.as_object().ok_or(err)?;
                obj.contains_key("bip9_softforks")
            };

            if is_legacy {
                // First, remove both incompatible softfork fields.
                // We need to scope the mutable ref here for v1.29 borrowck.
                let (bip9_softforks, old_softforks) = {
                    let map = raw.as_object_mut().ok_or(err)?;
                    let bip9_softforks = map.remove("bip9_softforks").ok_or(err)?;
                    let old_softforks = map.remove("softforks").ok_or(err)?;
                    // Put back an empty "softforks" field.
                    map.insert("softforks".into(), serde_json::Map::new().into());
                    (bip9_softforks, old_softforks)
                };
                let mut ret = serde_json::from_value::<json::GetBlockchainInfoResult>(raw)?;

                // Then convert both softfork types and add them.
                for sf in old_softforks.as_array().ok_or(err)?.iter() {
                    let json = sf.as_object().ok_or(err)?;
                    let id = json.get("id").ok_or(err)?.as_str().ok_or(err)?;
                    let reject = json.get("reject").ok_or(err)?.as_object().ok_or(err)?;
                    let active = reject.get("status").ok_or(err)?.as_bool().ok_or(err)?;
                    ret.softforks.insert(
                        id.into(),
                        json::Softfork {
                            type_: json::SoftforkType::Buried,
                            bip9: None,
                            height: None,
                            active: active,
                        },
                    );
                }
                for (id, sf) in bip9_softforks.as_object().ok_or(err)?.iter() {
                    #[derive(Deserialize)]
                    struct OldBip9SoftFork {
                        pub status: json::Bip9SoftforkStatus,
                        pub bit: Option<u8>,
                        #[serde(rename = "startTime")]
                        pub start_time: i64,
                        pub timeout: u64,
                        pub since: u32,
                        pub statistics: Option<json::Bip9SoftforkStatistics>,
                    }
                    let sf: OldBip9SoftFork = serde_json::from_value(sf.clone())?;
                    ret.softforks.insert(
                        id.clone(),
                        json::Softfork {
                            type_: json::SoftforkType::Bip9,
                            bip9: Some(json::Bip9SoftforkInfo {
                                status: sf.status,
                                bit: sf.bit,
                                start_time: sf.start_time,
                                timeout: sf.timeout,
                                since: sf.since,
                                statistics: sf.statistics,
                            }),
                            height: None,
                            active: sf.status == json::Bip9SoftforkStatus::Active,
                        },
                    );
                }
                Ok(ret)
            } else {
                Ok(serde_json::from_value(raw)?)
            }
        },
    }
}

#[inline(always)]
pub fn get_block_count() -> Request<'static, u64> {
    Request {
        method: "getblockcount".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_best_block_hash() -> Request<'static, bitcoin::BlockHash> {
    Request {
        method: "getbestblockhash".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

/// Get block hash at a given height
#[inline(always)]
pub fn get_block_hash(height: u64) -> Request<'static, bitcoin::BlockHash> {
    Request {
        method: "getblockhash".into(),
        params: params![
            ("height", v(height)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_block_stats<'r>(
    block_ref: &'r impl BlockRef,
) -> Request<'r, json::GetBlockStatsResult> {
    Request {
        method: "getblockstats".into(),
        params: params![
            ("hash_or_height", r(block_ref)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_block_stats_fields<'r>(
    block_ref: &'r impl BlockRef,
    fields: &'r &'r [json::BlockStatsFields],
) -> Request<'r, json::GetBlockStatsResultPartial> {
    Request {
        method: "getblockstats".into(),
        params: params![
            ("hash_or_height", r(block_ref)),
            ("stats", r(fields)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_raw_transaction<'r>(
    txid: &'r bitcoin::Txid,
    block_hash: Option<&'r bitcoin::BlockHash>,
) -> Request<'r, Transaction> {
    Request {
        method: "getrawtransaction".into(),
        params: params![
            ("txid", r(txid)),
            ("verbose", v(false)),
            ?("blockhash", or(block_hash)),
        ],
        converter: &|raw| converter_hex(raw),
    }
}

#[inline(always)]
pub fn get_raw_transaction_hex<'r>(
    txid: &'r bitcoin::Txid,
    block_hash: Option<&'r bitcoin::BlockHash>,
) -> Request<'r, String> {
    Request {
        method: "getrawtransaction".into(),
        params: params![
            ("txid", r(txid)),
            ("verbose", v(false)),
            ?("blockhash", or(block_hash)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_raw_transaction_info<'r>(
    txid: &'r bitcoin::Txid,
    block_hash: Option<&'r bitcoin::BlockHash>,
) -> Request<'r, json::GetRawTransactionResult> {
    Request {
        method: "getrawtransaction".into(),
        params: params![
            ("txid", r(txid)),
            ("verbose", v(true)),
            ?("blockhash", or(block_hash)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_block_filter<'r>(
    block_hash: &'r bitcoin::BlockHash,
) -> Request<'r, json::GetBlockFilterResult> {
    Request {
        method: "getblockfilter".into(),
        params: params![
            ("blockhash", r(block_hash)),
            // filtertype?
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_balance(
    minconf: Option<usize>,
    include_watchonly: Option<bool>,
) -> Request<'static, Amount> {
    Request {
        method: "getbalance".into(),
        params: params![
            // we don't need to provide the dummy argument because we use named args
            ?("minconf", ov(minconf)),
            ?("include_watchonly", ov(include_watchonly)),
            //TODO(stevenroose) missing avoid_reuse
        ],
        converter: &|raw| converter_btc(raw),
    }
}

#[inline(always)]
pub fn get_balances() -> Request<'static, json::GetBalancesResult> {
    Request {
        method: "getbalances".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_received_by_address<'r>(
    address: &'r StringSerializeWrapper<'r, impl AddressParam + ?Sized>,
    minconf: Option<u32>,
) -> Request<'r, Amount> {
    Request {
        method: "getreceivedbyaddress".into(),
        params: params![
            ("address", r(address)),
            ?("minconf", ov(minconf)),
        ],
        converter: &|raw| converter_btc(raw),
    }
}

#[inline(always)]
pub fn get_transaction<'r>(
    txid: &'r bitcoin::Txid,
    include_watchonly: Option<bool>,
    support_verbose: bool,
) -> Request<'r, json::GetTransactionResult> {
    Request {
        method: "gettransaction".into(),
        params: if support_verbose {
            params![
                ("txid", r(txid)),
                ("verbose", v(false)),
                ?("include_watchonly", ov(include_watchonly)),
            ]
        } else {
            params![
                ("txid", r(txid)),
                ?("include_watchonly", ov(include_watchonly)),
            ]
        },
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn list_transactions<'r>(
    label: Option<&'r &'r str>,
    count: Option<usize>,
    skip: Option<usize>,
    include_watchonly: Option<bool>,
) -> Request<'r, Vec<json::ListTransactionResult>> {
    Request {
        method: "listtransactions".into(),
        params: params![
            ?("label", or(label)),
            ?("count", ov(count)),
            ?("skip", ov(skip)),
            ?("include_watchonly", ov(include_watchonly)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn list_since_block<'r>(
    block_hash: Option<&'r bitcoin::BlockHash>,
    target_confirmations: Option<usize>,
    include_watchonly: Option<bool>,
    include_removed: Option<bool>,
) -> Request<'r, json::ListSinceBlockResult> {
    Request {
        method: "listsinceblock".into(),
        params: params![
            ?("blockhash", or(block_hash)),
            ?("target_confirmations", ov(target_confirmations)),
            ?("include_watchonly", ov(include_watchonly)),
            ?("include_removed", ov(include_removed)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_tx_out<'r>(
    txid: &'r bitcoin::Txid,
    vout: u32,
    include_mempool: Option<bool>,
) -> Request<'r, Option<json::GetTxOutResult>> {
    Request {
        method: "gettxout".into(),
        params: params![
            ("txid", r(txid)),
            ("n", v(vout)),
            ?("include_mempool", ov(include_mempool)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_tx_out_proof<'r>(
    txids: &'r &'r [bitcoin::Txid],
    block_hash: Option<&'r bitcoin::BlockHash>,
) -> Request<'r, Vec<u8>> {
    Request {
        method: "gettxoutproof".into(),
        params: params![
            ("txids", r(txids)),
            ?("blockhash", or(block_hash)),
        ],
        converter: &|raw| converter_raw_hex(raw),
    }
}

#[inline(always)]
pub fn import_public_key<'r>(
    public_key: &'r PublicKey,
    label: Option<&'r &'r str>,
    rescan: Option<bool>,
) -> Request<'r, ()> {
    Request {
        method: "importpubkey".into(),
        params: params![
            ("pubkey", r(public_key)),
            ?("label", or(label)),
            ?("rescan", ov(rescan)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn import_private_key<'r>(
    private_key: &'r PrivateKey,
    label: Option<&'r &'r str>,
    rescan: Option<bool>,
) -> Request<'r, ()> {
    Request {
        method: "importprivkey".into(),
        params: params![
            ("privkey", r(private_key)),
            ?("label", or(label)),
            ?("rescan", ov(rescan)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn import_address<'r>(
    address: &'r StringSerializeWrapper<'r, impl AddressParam + ?Sized>,
    label: Option<&'r &'r str>,
    rescan: Option<bool>,
) -> Request<'r, ()> {
    Request {
        method: "importaddress".into(),
        params: params![
            ("address", r(address)),
            ?("label", or(label)),
            ?("rescan", ov(rescan)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn import_address_script<'r>(
    script: &'r ScriptBuf,
    label: Option<&'r &'r str>,
    rescan: Option<bool>,
    p2sh: Option<bool>,
) -> Request<'r, ()> {
    Request {
        method: "importaddress".into(),
        params: params![
            ("address", r(script)),
            ?("label", or(label)),
            ?("rescan", ov(rescan)),
            ?("p2sh", ov(p2sh)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn import_multi<'r>(
    requests: &'r &'r [json::ImportMultiRequest],
    options: Option<&'r json::ImportMultiOptions>,
) -> Request<'r, Vec<json::ImportMultiResult>> {
    Request {
        method: "importmulti".into(),
        params: params![
            ("requests", r(requests)),
            ?("options", or(options)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn import_descriptors<'r>(
    requests: &'r &'r [json::ImportDescriptors],
) -> Request<'r, Vec<json::ImportMultiResult>> {
    Request {
        method: "importdescriptors".into(),
        params: params![
            ("requests", r(requests)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn set_label<'r>(
    address: &'r StringSerializeWrapper<'r, impl AddressParam + ?Sized>,
    label: &'r &'r str,
) -> Request<'r, ()> {
    Request {
        method: "setlabel".into(),
        params: params![
            ("address", r(address)),
            ("label", r(label)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn key_pool_refill(new_size: Option<usize>) -> Request<'static, ()> {
    Request {
        method: "keypoolrefill".into(),
        params: params![
            ?("newsize", ov(new_size)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn list_unspent<'r>(
    minconf: Option<usize>,
    maxconf: Option<usize>,
    addresses: Option<&'r StringListSerializeWrapper<'r, impl AddressParam>>,
    include_unsafe: Option<bool>,
    query_options: Option<&'r json::ListUnspentQueryOptions>,
) -> Request<'r, Vec<json::ListUnspentResultEntry>> {
    Request {
        method: "listunspent".into(),
        params: params![
            ?("minconf", ov(minconf)),
            ?("maxconf", ov(maxconf)),
            ?("addresses", or(addresses)),
            ?("include_unsafe", ov(include_unsafe)),
            ?("query_options", or(query_options)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

/// To unlock, use [unlock_unspent].
#[inline(always)]
pub fn lock_unspent<'r>(outputs: &'r OutPointListObjectSerializeWrapper) -> Request<'r, bool> {
    Request {
        method: "lockunspent".into(),
        params: params![
            ("unlock", v(false)),
            ("transactions", r(outputs)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn unlock_unspent<'r>(outputs: &'r OutPointListObjectSerializeWrapper) -> Request<'r, bool> {
    Request {
        method: "lockunspent".into(),
        params: params![
            ("unlock", v(true)),
            ("transactions", r(outputs)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn unlock_unspent_all() -> Request<'static, bool> {
    Request {
        method: "lockunspent".into(),
        params: params![
            ("unlock", v(true)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn list_received_by_address<'r>(
    address_filter: Option<&'r StringSerializeWrapper<'r, impl AddressParam + ?Sized>>,
    minconf: Option<u32>,
    include_empty: Option<bool>,
    include_watchonly: Option<bool>,
) -> Request<'r, Vec<json::ListReceivedByAddressResult>> {
    Request {
        method: "listreceivedbyaddress".into(),
        params: params![
            ?("minconf", ov(minconf)),
            ?("include_empty", ov(include_empty)),
            ?("include_watchonly", ov(include_watchonly)),
            ?("address_filter", or(address_filter)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn create_raw_transaction_hex<'r>(
    inputs: &'r &'r [json::CreateRawTransactionInput],
    outputs: &'r &'r [json::CreateRawTransactionOutput],
    locktime: Option<i64>,
    replaceable: Option<bool>,
) -> Request<'r, String> {
    Request {
        method: "createrawtransaction".into(),
        params: params![
            ("inputs", r(inputs)),
            ("outputs", r(outputs)),
            ?("locktime", ov(locktime)),
            ?("replaceable", ov(replaceable)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn create_raw_transaction<'r>(
    inputs: &'r &'r [json::CreateRawTransactionInput],
    outputs: &'r &'r [json::CreateRawTransactionOutput],
    locktime: Option<i64>,
    replaceable: Option<bool>,
) -> Request<'r, Transaction> {
    Request {
        method: "createrawtransaction".into(),
        params: params![
            ("inputs", r(inputs)),
            ("outputs", r(outputs)),
            ?("locktime", ov(locktime)),
            ?("replaceable", ov(replaceable)),
        ],
        converter: &|raw| converter_hex(raw),
    }
}

#[inline(always)]
pub fn decode_raw_transaction<'r>(
    tx: &'r HexSerializeWrapper<'r, impl TxParam + ?Sized>,
    is_witness: Option<bool>,
) -> Request<'r, json::DecodeRawTransactionResult> {
    Request {
        method: "decoderawtransaction".into(),
        params: params![
            ("hexstring", r(tx)),
            ?("iswitness", ov(is_witness)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn fund_raw_transaction<'r>(
    tx: &'r HexSerializeWrapper<'r, impl TxParam + ?Sized>,
    options: Option<&'r json::FundRawTransactionOptions>,
    is_witness: Option<bool>,
) -> Request<'r, json::FundRawTransactionResult> {
    Request {
        method: "fundrawtransaction".into(),
        params: params![
            ("hexstring", r(tx)),
            ?("options", or(options)),
            ?("iswitness", ov(is_witness)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn sign_raw_transaction_with_wallet<'r>(
    tx: &'r HexSerializeWrapper<'r, impl TxParam + ?Sized>,
    inputs: Option<&'r &'r [json::SignRawTransactionInput]>,
    sighash_type: Option<&'r StringSerializeWrapper<impl SighashParam>>,
) -> Request<'r, json::SignRawTransactionResult> {
    Request {
        method: "signrawtransactionwithwallet".into(),
        params: params![
            ("hexstring", r(tx)),
            ?("prevtxs", or(inputs)),
            ?("sighashtype", or(sighash_type)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn sign_raw_transaction_with_key<'r>(
    tx: &'r HexSerializeWrapper<'r, impl TxParam + ?Sized>,
    privkeys: &'r &'r [PrivateKey],
    inputs: Option<&'r &'r [json::SignRawTransactionInput]>,
    sighash_type: Option<&'r StringSerializeWrapper<impl SighashParam>>,
) -> Request<'r, json::SignRawTransactionResult> {
    Request {
        method: "signrawtransactionwithkey".into(),
        params: params![
            ("hexstring", r(tx)),
            ("privkeys", r(privkeys)),
            ?("prevtxs", or(inputs)),
            // avoid allocation
            ?("sighashtype", or(sighash_type)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

/// Fee rate per kvb.
#[inline(always)]
pub fn test_mempool_accept<'r>(
    raw_txs: &'r HexListSerializeWrapper<'r, impl TxParam>,
    max_fee_rate_btc_per_kvb: Option<f64>,
) -> Request<'r, Vec<json::TestMempoolAcceptResult>> {
    Request {
        method: "testmempoolaccept".into(),
        params: params![
            ("rawtxs", r(raw_txs)),
            ?("maxfeerate", ov(max_fee_rate_btc_per_kvb)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn stop() -> Request<'static, String> {
    Request {
        method: "stop".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn verify_message<'r>(
    address: &'r StringSerializeWrapper<'r, impl AddressParam + ?Sized>,
    signature: &'r Signature,
    message: &'r &'r str,
) -> Request<'r, bool> {
    Request {
        method: "verifymessage".into(),
        params: params![
            ("address", r(address)),
            ("signature", r(signature)),
            ("message", r(message)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_new_address<'r>(
    label: Option<&'r &'r str>,
    address_type: Option<&'r json::AddressType>,
) -> Request<'r, UncheckedAddress> {
    Request {
        method: "getnewaddress".into(),
        params: params![
            ?("label", or(label)),
            ?("address_type", or(address_type)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_raw_change_address<'r>(
    address_type: Option<&'r json::AddressType>,
) -> Request<'r, UncheckedAddress> {
    Request {
        method: "getrawchangeaddress".into(),
        params: params![
            ?("address_type", or(address_type)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_address_info<'r>(
    address: &'r StringSerializeWrapper<'r, impl AddressParam + ?Sized>,
) -> Request<'r, json::GetAddressInfoResult> {
    Request {
        method: "getaddressinfo".into(),
        params: params![
            ("address", r(address)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn generate_to_address<'r>(
    block_num: u64,
    address: &'r StringSerializeWrapper<'r, impl AddressParam + ?Sized>,
    max_tries: Option<usize>,
) -> Request<'r, Vec<bitcoin::BlockHash>> {
    Request {
        method: "generatetoaddress".into(),
        params: params![
            ("nblocks", v(block_num)),
            ("address", r(address)),
            ?("maxtries", ov(max_tries)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn generate(
    block_num: u64,
    max_tries: Option<usize>,
) -> Request<'static, Vec<bitcoin::BlockHash>> {
    // Special case for generate we use positional arguments.
    // This is a deprecated call.

    let params = if let Some(max_tries) = max_tries {
        vec![v(block_num), v(max_tries)]
    } else {
        vec![v(block_num)]
    };
    Request {
        method: "generate".into(),
        params: Params::ByPosition(List::Boxed(params.into())),
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn invalidate_block<'r>(block_hash: &'r bitcoin::BlockHash) -> Request<'r, ()> {
    Request {
        method: "invalidateblock".into(),
        params: params![
            ("blockhash", r(block_hash)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn reconsider_block<'r>(block_hash: &'r bitcoin::BlockHash) -> Request<'r, ()> {
    Request {
        method: "reconsiderblock".into(),
        params: params![
            ("blockhash", r(block_hash)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_mempool_info() -> Request<'static, json::GetMempoolInfoResult> {
    Request {
        method: "getmempoolinfo".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_raw_mempool() -> Request<'static, Vec<bitcoin::Txid>> {
    Request {
        method: "getrawmempool".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_mempool_entry<'r>(txid: &'r bitcoin::Txid) -> Request<'r, json::GetMempoolEntryResult> {
    Request {
        method: "getmempoolentry".into(),
        params: params![
            ("txid", r(txid)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_chain_tips() -> Request<'static, json::GetChainTipsResult> {
    Request {
        method: "getchaintips".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn send_to_address<'r>(
    address: &'r StringSerializeWrapper<'r, impl AddressParam + ?Sized>,
    amount: Amount,
    comment: Option<&'r &'r str>,
    comment_to: Option<&'r &'r str>,
    subtract_fee: Option<bool>,
    replaceable: Option<bool>,
    confirmation_target: Option<u32>,
    estimate_mode: Option<&'r json::EstimateMode>,
    avoid_reuse: Option<bool>,
    support_verbose: bool,
    fee_rate_sat_per_vb: Option<u64>,
) -> Request<'r, bitcoin::Txid> {
    Request {
        method: "sendtoaddress".into(),
        params: if support_verbose {
            params![
                ("address", r(address)),
                ("amount", v(amount.to_btc())),
                ("verbose", v(false)),
                ?("comment", or(comment)),
                ?("comment_to", or(comment_to)),
                ?("subtractfeefromamount", ov(subtract_fee)),
                ?("replaceable", ov(replaceable)),
                ?("conf_target", ov(confirmation_target)),
                ?("estimate_mode", or(estimate_mode)),
                ?("avoid_reuse", ov(avoid_reuse)),
                ?("fee_rate", ov(fee_rate_sat_per_vb)),
            ]
        } else {
            params![
                ("address", r(address)),
                ("amount", v(amount.to_btc())),
                ?("comment", or(comment)),
                ?("comment_to", or(comment_to)),
                ?("subtractfeefromamount", ov(subtract_fee)),
                ?("replaceable", ov(replaceable)),
                ?("conf_target", ov(confirmation_target)),
                ?("estimate_mode", or(estimate_mode)),
                ?("avoid_reuse", ov(avoid_reuse)),
                // pre-verbose also doesn't support feerate, but let's let core
                // produce an error in case the user thinks it's setting a fee
                // rate instead of silently dropping it
                ?("fee_rate", ov(fee_rate_sat_per_vb)),
            ]
        },
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn add_node<'r>(addr: &'r &'r str) -> Request<'r, ()> {
    Request {
        method: "addnode".into(),
        params: params![
            ("node", r(addr)),
            ("command", r(&"add")),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn add_node_onetry<'r>(addr: &'r &'r str) -> Request<'r, ()> {
    Request {
        method: "addnode".into(),
        params: params![
            ("node", r(addr)),
            ("command", r(&"onetry")),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn remove_node<'r>(addr: &'r &'r str) -> Request<'r, ()> {
    Request {
        method: "addnode".into(),
        params: params![
            ("node", r(addr)),
            ("command", r(&"remove")),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn disconnect_node<'r>(addr: &'r &'r str) -> Request<'r, ()> {
    Request {
        method: "disconnectnode".into(),
        params: params![
            ("address", r(addr)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn disconnect_node_by_id(node_id: u32) -> Request<'static, ()> {
    Request {
        method: "disconnectnode".into(),
        params: params![
            ("nodeid", v(node_id)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_added_node_info<'r>(
    node: &'r &'r str,
) -> Request<'r, Vec<json::GetAddedNodeInfoResult>> {
    Request {
        method: "getaddednodeinfo".into(),
        params: params![
            ("node", r(node)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_added_nodes_info() -> Request<'static, Vec<json::GetAddedNodeInfoResult>> {
    Request {
        method: "getaddednodeinfo".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_node_addresses(
    count: Option<usize>,
) -> Request<'static, Vec<json::GetNodeAddressesResult>> {
    Request {
        method: "getnodeaddresses".into(),
        params: params![
            ?("count", ov(count)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

/// List all banned IPs/Subnets.
#[inline(always)]
pub fn list_banned() -> Request<'static, Vec<json::ListBannedResult>> {
    Request {
        method: "listbanned".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

/// Clear all banned IPs.
#[inline(always)]
pub fn clear_banned() -> Request<'static, ()> {
    Request {
        method: "clearbanned".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

/// Attempts to add an IP/Subnet to the banned list.
#[inline(always)]
pub fn add_ban<'r>(subnet: &'r &'r str, bantime: u64, absolute: bool) -> Request<'r, ()> {
    Request {
        method: "setban".into(),
        params: params![
            ("subnet", r(subnet)),
            ("command", r(&"add")),
            ("bantime", v(bantime)),
            ("absolute", v(absolute)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

/// Attempts to remove an IP/Subnet from the banned list.
#[inline(always)]
pub fn remove_ban<'r>(subnet: &'r &'r str) -> Request<'r, ()> {
    Request {
        method: "setban".into(),
        params: params![
            ("subnet", r(subnet)),
            ("command", r(&"remove")),
        ],
        converter: &|raw| converter_json(raw),
    }
}

/// Disable/enable all p2p network activity.
#[inline(always)]
pub fn set_network_active(state: bool) -> Request<'static, bool> {
    Request {
        method: "setnetworkactive".into(),
        params: params![
            ("state", v(state)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_peer_info() -> Request<'static, Vec<json::GetPeerInfoResult>> {
    Request {
        method: "getpeerinfo".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn ping() -> Request<'static, ()> {
    Request {
        method: "ping".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn send_raw_transaction<'r>(
    tx: &'r HexSerializeWrapper<'r, impl TxParam + ?Sized>,
) -> Request<'r, bitcoin::Txid> {
    Request {
        method: "sendrawtransaction".into(),
        params: params![
            ("hexstring", r(tx)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn estimate_smart_fee<'r>(
    conf_target: u16,
    estimate_mode: Option<&'r json::EstimateMode>,
) -> Request<'r, json::EstimateSmartFeeResult> {
    Request {
        method: "estimatesmartfee".into(),
        params: params![
            ("conf_target", v(conf_target)),
            ?("estimate_mode", or(estimate_mode)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn wait_for_new_block(timeout: Option<u64>) -> Request<'static, json::BlockRef> {
    Request {
        method: "waitfornewblock".into(),
        params: params![
            ?("timeout", ov(timeout)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn wait_for_block<'r>(
    block_hash: &'r bitcoin::BlockHash,
    timeout: Option<u64>,
) -> Request<'r, json::BlockRef> {
    Request {
        method: "waitforblock".into(),
        params: params![
            ("blockhash", r(block_hash)),
            ?("timeout", ov(timeout)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn create_psbt_raw<'r>(
    inputs: &'r &'r [json::CreateRawTransactionInput],
    outputs: &'r &'r [json::CreateRawTransactionOutput],
    locktime: Option<i64>,
    replaceable: Option<bool>,
) -> Request<'r, String> {
    Request {
        method: "createpsbt".into(),
        params: params![
            ("inputs", r(inputs)),
            ("outputs", r(outputs)),
            ?("locktime", ov(locktime)),
            ?("replaceable", ov(replaceable)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn create_psbt<'r>(
    inputs: &'r &'r [json::CreateRawTransactionInput],
    outputs: &'r &'r [json::CreateRawTransactionOutput],
    locktime: Option<i64>,
    replaceable: Option<bool>,
) -> Request<'r, PartiallySignedTransaction> {
    Request {
        method: "createpsbt".into(),
        params: params![
            ("inputs", r(inputs)),
            ("outputs", r(outputs)),
            ?("locktime", ov(locktime)),
            ?("replaceable", ov(replaceable)),
        ],
        converter: &|raw| converter_psbt(raw),
    }
}

#[inline(always)]
pub fn wallet_create_funded_psbt<'r>(
    inputs: &'r &'r [json::CreateRawTransactionInput],
    outputs: &'r &'r [json::CreateRawTransactionOutput],
    locktime: Option<i64>,
    options: Option<&'r json::WalletCreateFundedPsbtOptions>,
    include_bip32_derivations: Option<bool>,
) -> Request<'r, json::WalletCreateFundedPsbtResult> {
    Request {
        method: "walletcreatefundedpsbt".into(),
        params: params![
            ("inputs", r(inputs)),
            ("outputs", r(outputs)),
            ?("locktime", ov(locktime)),
            ?("options", or(options)),
            ?("bip32derivs", ov(include_bip32_derivations)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn wallet_process_psbt<'r>(
    psbt: &'r StringSerializeWrapper<impl PsbtParam + ?Sized>,
    sign: Option<bool>,
    sighash_type: Option<&'r json::SigHashType>,
    include_bip32_derivations: Option<bool>,
) -> Request<'r, json::WalletProcessPsbtResult> {
    Request {
        method: "walletprocesspsbt".into(),
        params: params![
            ("psbt", r(psbt)),
            ?("sign", ov(sign)),
            ?("sighashtype", or(sighash_type)),
            ?("bip32derivs", ov(include_bip32_derivations)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn join_psbts_raw<'r>(
    psbts: &'r StringListSerializeWrapper<'r, impl PsbtParam>,
) -> Request<'r, String> {
    Request {
        method: "joinpsbts".into(),
        params: params![
            ("txs", r(psbts)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn join_psbts<'r>(
    psbts: &'r StringListSerializeWrapper<'r, impl PsbtParam>,
) -> Request<'r, PartiallySignedTransaction> {
    Request {
        method: "joinpsbts".into(),
        params: params![
            ("txs", r(psbts)),
        ],
        converter: &|raw| converter_psbt(raw),
    }
}

#[inline(always)]
pub fn combine_psbt_raw<'r>(
    psbts: &'r StringListSerializeWrapper<'r, impl PsbtParam>,
) -> Request<'r, String> {
    Request {
        method: "combinepsbt".into(),
        params: params![
            ("txs", r(psbts)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn combine_psbt<'r>(
    psbts: &'r StringListSerializeWrapper<'r, impl PsbtParam>,
) -> Request<'r, PartiallySignedTransaction> {
    Request {
        method: "combinepsbt".into(),
        params: params![
            ("txs", r(psbts)),
        ],
        converter: &|raw| converter_psbt(raw),
    }
}

#[inline(always)]
pub fn combine_raw_transaction_hex<'r>(
    txs: &'r HexListSerializeWrapper<'r, impl TxParam>,
) -> Request<'r, String> {
    Request {
        method: "combinerawtransaction".into(),
        params: params![
            ("txs", r(txs)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn combine_raw_transaction<'r>(
    txs: &'r HexListSerializeWrapper<'r, impl TxParam>,
) -> Request<'r, Transaction> {
    Request {
        method: "combinerawtransaction".into(),
        params: params![
            ("txs", r(txs)),
        ],
        converter: &|raw| converter_hex(raw),
    }
}

#[inline(always)]
pub fn finalize_psbt<'r>(
    psbt: &'r StringSerializeWrapper<impl PsbtParam + ?Sized>,
    extract: Option<bool>,
) -> Request<'r, json::FinalizePsbtResult> {
    Request {
        method: "finalizepsbt".into(),
        params: params![
            ("psbt", r(psbt)),
            ?("extract", ov(extract)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_descriptor_info<'r>(
    descriptor: &'r &'r str,
) -> Request<'r, json::GetDescriptorInfoResult> {
    Request {
        method: "getdescriptorinfo".into(),
        params: params![
            ("descriptor", r(descriptor)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn derive_addresses<'r>(
    descriptor: &'r &'r str,
    range: Option<&'r [u32; 2]>,
) -> Request<'r, Vec<UncheckedAddress>> {
    Request {
        method: "deriveaddresses".into(),
        params: params![
            ("descriptor", r(descriptor)),
            ?("range", or(range)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn rescan_blockchain(
    start_height: Option<usize>,
    stop_height: Option<usize>,
) -> Request<'static, (usize, Option<usize>)> {
    Request {
        method: "rescanblockchain".into(),
        params: params![
            ?("start_height", ov(start_height)),
            ?("stop_height", ov(stop_height)),
        ],
        converter: &|raw| {
            #[derive(Deserialize)]
            struct Response {
                start_height: usize,
                stop_height: Option<usize>,
            }
            let ret = serde_json::from_str::<Response>(raw.get())?;
            Ok((ret.start_height, ret.stop_height))
        },
    }
}

#[inline(always)]
pub fn get_tx_out_set_info<'r>(
    hash_type: Option<&'r json::TxOutSetHashType>,
    target_block_ref: Option<&'r impl BlockRef>,
    use_index: Option<bool>,
) -> Request<'r, json::GetTxOutSetInfoResult> {
    Request {
        method: "gettxoutsetinfo".into(),
        params: params![
            ?("hash_type", or(hash_type)),
            ?("hash_or_height", or(target_block_ref)),
            ?("use_index", ov(use_index)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_net_totals() -> Request<'static, json::GetNetTotalsResult> {
    Request {
        method: "getnettotals".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn get_network_hash_ps(
    nb_blocks: Option<u64>,
    height: Option<u64>,
) -> Request<'static, f64> {
    Request {
        method: "getnetworkhashps".into(),
        params: params![
            ?("nblocks", ov(nb_blocks)),
            ?("height", ov(height)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

/// Returns the total uptime of the server in seconds
#[inline(always)]
pub fn uptime() -> Request<'static, u64> {
    Request {
        method: "uptime".into(),
        params: params![],
        converter: &|raw| converter_json(raw),
    }
}

#[inline(always)]
pub fn submit_block<'r>(
    block: &'r HexSerializeWrapper<'r, impl BlockParam + ?Sized>,
) -> Request<'r, ()> {
    Request {
        method: "submitblock".into(),
        params: params![
            ("block", r(block)),
        ],
        converter: &|raw| converter_expect_null(raw),
    }
}

#[inline(always)]
pub fn scan_tx_out_set_blocking<'r>(
    descriptors: &'r &'r [json::ScanTxOutRequest],
) -> Request<'r, json::ScanTxOutResult> {
    Request {
        method: "scantxoutset".into(),
        params: params![
            ("action", r(&"start")),
            ("scanobjects", r(descriptors)),
        ],
        converter: &|raw| converter_json(raw),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::Value;

    /// Shorthand for `serde_json::Value::Null`.
    fn null() -> Param<'static> {
        Param::Value(Value::Null)
    }

    #[test]
    fn test_params_macro() {
        let params = params![
            ("test1", null()),
            ?("test2", Some(null())),
            ?("test3", None),
        ];
        match params {
            Params::ByPosition(_) => panic!(),
            Params::ByName(p) => {
                assert_eq!(p.as_slice().len(), 2);
                assert_eq!(serde_json::to_string(&p.as_slice()[0].1).unwrap(), "null");
                assert_eq!(serde_json::to_string(&p.as_slice()[1].1).unwrap(), "null");
            }
        }
    }
}
