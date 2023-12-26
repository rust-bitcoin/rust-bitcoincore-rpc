use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor};
use std::iter::FromIterator;
use std::path::PathBuf;
use std::{fmt, result};
use hex::FromHex;

use jsonrpc;
use serde;
use serde_json;

use log::Level::{Debug, Trace, Warn};
use sv::messages::{Block, BlockHeader};
use sv::util::Serializable;
use bitcoinsv_rpc_json::{Tx, TxHash, BlockHash, Amount, GetNetworkInfoResult};

use crate::error::*;
use crate::json;

/// Crate-specific Result type, shorthand for `std::result::Result` with our
/// crate-specific Error type;
pub type Result<T> = result::Result<T, Error>;

/// Outpoint that serializes and deserializes as a map, instead of a string,
/// for use as RPC arguments
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonOutPoint {
    pub txid: TxHash,
    pub vout: u32,
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
                if defaults[defaults_i] == serde_json::Value::Null {
                    panic!("Missing `default` for argument idx {}", args_i);
                }
                args[args_i] = defaults[defaults_i].clone();
            }
        } else if first_non_null_optional_idx.is_none() {
            first_non_null_optional_idx = Some(args_i);
        }
    }

    let required_num = args.len() - defaults.len();

    if let Some(i) = first_non_null_optional_idx {
        &args[..i + 1]
    } else {
        &args[..required_num]
    }
}

/// Convert a possible-null result into an Option.
fn opt_result<T: for<'a> serde::de::Deserialize<'a>>(
    result: serde_json::Value,
) -> Result<Option<T>> {
    if result == serde_json::Value::Null {
        Ok(None)
    } else {
        Ok(serde_json::from_value(result)?)
    }
}

/// Used to pass raw txs into the API.
pub trait RawTx: Sized + Clone {
    fn raw_hex(self) -> String;
}

impl<'a> RawTx for &'a Tx {
    fn raw_hex(self) -> String {
        let mut buf = Vec::new();
        self.write(&mut buf).unwrap();
        hex::encode(buf)
    }
}

impl<'a> RawTx for &'a [u8] {
    fn raw_hex(self) -> String {
        hex::encode(self)
    }
}

impl<'a> RawTx for &'a Vec<u8> {
    fn raw_hex(self) -> String {
        hex::encode(self)
    }
}

impl<'a> RawTx for &'a str {
    fn raw_hex(self) -> String {
        self.to_owned()
    }
}

impl RawTx for String {
    fn raw_hex(self) -> String {
        self
    }
}

/// The different authentication methods for the client.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum Auth {
    None,
    UserPass(String, String),
    CookieFile(PathBuf),
}

impl Auth {
    /// Convert into the arguments that jsonrpc::Client needs.
    pub fn get_user_pass(self) -> Result<(Option<String>, Option<String>)> {
        match self {
            Auth::None => Ok((None, None)),
            Auth::UserPass(u, p) => Ok((Some(u), Some(p))),
            Auth::CookieFile(path) => {
                let line = BufReader::new(File::open(path)?)
                    .lines()
                    .next()
                    .ok_or(Error::InvalidCookieFile)??;
                let colon = line.find(':').ok_or(Error::InvalidCookieFile)?;
                Ok((Some(line[..colon].into()), Some(line[colon + 1..].into())))
            }
        }
    }
}

pub trait RpcApi: Sized {
    /// Call a `cmd` rpc with given `args` list
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T>;

    fn get_network_info(&self) -> Result<json::GetNetworkInfoResult> {
        self.call("getnetworkinfo", &[])
    }

    fn version(&self) -> Result<u32> {
        let res: GetNetworkInfoResult = self.call("getnetworkinfo", &[])?;
        Ok(res.version)
    }

    fn get_difficulty(&self) -> Result<f64> {
        self.call("getdifficulty", &[])
    }

    fn get_connection_count(&self) -> Result<usize> {
        self.call("getconnectioncount", &[])
    }

    fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        let hex: String = self.call("getblock", &[into_json(hash)?, 0.into()])?;
        let buf = hex::decode(hex)?;
        let mut c = Cursor::new(buf);
        Block::read(&mut c).map_err(Error::from)
    }

    fn get_block_hex(&self, hash: &BlockHash) -> Result<String> {
        self.call("getblock", &[into_json(hash)?, 0.into()])
    }

    fn get_block_info(&self, hash: &BlockHash) -> Result<json::GetBlockResult> {
        self.call("getblock", &[into_json(hash)?, 1.into()])
    }

    fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader> {
        let hex: String = self.call("getblockheader", &[into_json(hash)?, false.into()])?;
        let buf = hex::decode(hex)?;
        Ok(BlockHeader::read(&mut &buf[..])?)
    }

    fn get_block_header_info(
        &self,
        hash: &BlockHash,
    ) -> Result<json::GetBlockHeaderResult> {
        self.call("getblockheader", &[into_json(hash)?, true.into()])
    }

    fn get_mining_info(&self) -> Result<json::GetMiningInfoResult> {
        self.call("getmininginfo", &[])
    }

    fn get_block_template(
        &self,
        mode: json::GetBlockTemplateModes,
        capabilities: &[json::GetBlockTemplateCapabilities],
    ) -> Result<json::GetBlockTemplateResult> {
        #[derive(Serialize)]
        struct Argument<'a> {
            mode: json::GetBlockTemplateModes,
            capabilities: &'a [json::GetBlockTemplateCapabilities],
        }

        self.call(
            "getblocktemplate",
            &[into_json(Argument {
                mode: mode,
                capabilities: capabilities,
            })?],
        )
    }

    /// Returns a data structure containing various state info regarding
    /// blockchain processing.
    fn get_blockchain_info(&self) -> Result<json::GetBlockchainInfoResult> {
        let raw: serde_json::Value = self.call("getblockchaininfo", &[])?;
        Ok(serde_json::from_value(raw)?)
    }

    /// Returns the numbers of block in the longest chain.
    fn get_block_count(&self) -> Result<u64> {
        self.call("getblockcount", &[])
    }

    /// Returns the hash of the best (tip) block in the longest blockchain.
    fn get_best_block_hash(&self) -> Result<BlockHash> {
        self.call("getbestblockhash", &[])
    }

    /// Get block hash at a given height
    fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        self.call("getblockhash", &[height.into()])
    }

    fn get_block_stats(&self, height: u64) -> Result<json::GetBlockStatsResult> {
        self.call("getblockstats", &[height.into()])
    }

    fn get_block_stats_fields(
        &self,
        height: u64,
        fields: &[json::BlockStatsFields],
    ) -> Result<json::GetBlockStatsResultPartial> {
        self.call("getblockstats", &[height.into(), fields.into()])
    }

    fn get_raw_transaction(
        &self,
        tx_hash: &TxHash,
        block_hash: Option<&BlockHash>,
    ) -> Result<Tx> {
        let mut args = [into_json(tx_hash)?, into_json(false)?, opt_into_json(block_hash)?];
        let hex: String = self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))?;
        let buf = hex::decode(hex)?;
        Ok(Tx::read(&mut &buf[..])?)
    }

    fn get_raw_transaction_hex(
        &self,
        tx_hash: &TxHash,
        block_hash: Option<&BlockHash>,
    ) -> Result<String> {
        let mut args = [into_json(tx_hash)?, into_json(false)?, opt_into_json(block_hash)?];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))
    }

    fn get_raw_transaction_info(
        &self,
        tx_hash: &TxHash,
        block_hash: Option<&BlockHash>,
    ) -> Result<json::GetRawTransactionResult> {
        let mut args = [into_json(tx_hash)?, into_json(true)?, opt_into_json(block_hash)?];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))
    }

    fn get_tx_out(
        &self,
        tx_hash: &TxHash,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<json::GetTxOutResult>> {
        let mut args = [into_json(tx_hash)?, into_json(vout)?, opt_into_json(include_mempool)?];
        opt_result(self.call("gettxout", handle_defaults(&mut args, &[null()]))?)
    }

    fn get_tx_out_proof(
        &self,
        tx_hashes: &[TxHash],
        block_hash: Option<&BlockHash>,
    ) -> Result<Vec<u8>> {
        let mut args = [into_json(tx_hashes)?, opt_into_json(block_hash)?];
        let hex: String = self.call("gettxoutproof", handle_defaults(&mut args, &[null()]))?;
        Ok(FromHex::from_hex(&hex)?)
    }

    fn create_raw_transaction_hex(
        &self,
        utxos: &[json::CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<String> {
        let outs_converted = serde_json::Map::from_iter(
            outs.iter().map(|(k, v)| (k.clone(), serde_json::Value::from(v.to_string()))),
        );
        let mut args = [
            into_json(utxos)?,
            into_json(outs_converted)?,
            opt_into_json(locktime)?,
            opt_into_json(replaceable)?,
        ];
        let defaults = [into_json(0i64)?, null()];
        self.call("createrawtransaction", handle_defaults(&mut args, &defaults))
    }

    fn create_raw_transaction(
        &self,
        utxos: &[json::CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<Tx> {
        let hex: String = self.create_raw_transaction_hex(utxos, outs, locktime, replaceable)?;
        let buf = hex::decode(hex)?;
        Ok(Tx::read(&mut &buf[..])?)
    }

    fn decode_raw_transaction<R: RawTx>(
        &self,
        tx: R,
        is_witness: Option<bool>,
    ) -> Result<json::DecodeRawTransactionResult> {
        let mut args = [tx.raw_hex().into(), opt_into_json(is_witness)?];
        let defaults = [null()];
        self.call("decoderawtransaction", handle_defaults(&mut args, &defaults))
    }

    fn stop(&self) -> Result<String> {
        self.call("stop", &[])
    }

    /// Mark a block as invalid by `block_hash`
    fn invalidate_block(&self, block_hash: &BlockHash) -> Result<()> {
        self.call("invalidateblock", &[into_json(block_hash)?])
    }

    /// Mark a block as valid by `block_hash`
    fn reconsider_block(&self, block_hash: &BlockHash) -> Result<()> {
        self.call("reconsiderblock", &[into_json(block_hash)?])
    }

    /// Returns details on the active state of the TX memory pool
    fn get_mempool_info(&self) -> Result<json::GetMempoolInfoResult> {
        self.call("getmempoolinfo", &[])
    }

    /// Get txids of all transactions in a memory pool
    fn get_raw_mempool(&self) -> Result<Vec<TxHash>> {
        self.call("getrawmempool", &[])
    }

    /// Get details for the transactions in a memory pool
    fn get_raw_mempool_verbose(
        &self,
    ) -> Result<HashMap<TxHash, json::GetMempoolEntryResult>> {
        self.call("getrawmempool", &[into_json(true)?])
    }

    /// Get mempool data for given transaction
    fn get_mempool_entry(&self, tx_hash: &TxHash) -> Result<json::GetMempoolEntryResult> {
        self.call("getmempoolentry", &[into_json(tx_hash)?])
    }

    /// Get information about all known tips in the block tree, including the
    /// main chain as well as stale branches.
    fn get_chain_tips(&self) -> Result<json::GetChainTipsResult> {
        self.call("getchaintips", &[])
    }

    /// Attempts to add a node to the addnode list.
    /// Nodes added using addnode (or -connect) are protected from DoS disconnection and are not required to be full nodes/support SegWit as other outbound peers are (though such peers will not be synced from).
    fn add_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", &[into_json(&addr)?, into_json("add")?])
    }

    /// Attempts to remove a node from the addnode list.
    fn remove_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", &[into_json(&addr)?, into_json("remove")?])
    }

    /// Attempts to connect to a node without permanently adding it to the addnode list.
    fn onetry_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", &[into_json(&addr)?, into_json("onetry")?])
    }

    /// Immediately disconnects from the specified peer node.
    fn disconnect_node(&self, addr: &str) -> Result<()> {
        self.call("disconnectnode", &[into_json(&addr)?])
    }

    fn disconnect_node_by_id(&self, node_id: u32) -> Result<()> {
        self.call("disconnectnode", &[into_json("")?, into_json(node_id)?])
    }

    /// Returns information about the given added node, or all added nodes (note that onetry addnodes are not listed here)
    fn get_added_node_info(&self, node: Option<&str>) -> Result<Vec<json::GetAddedNodeInfoResult>> {
        if let Some(addr) = node {
            self.call("getaddednodeinfo", &[into_json(&addr)?])
        } else {
            self.call("getaddednodeinfo", &[])
        }
    }

    /// List all banned IPs/Subnets.
    fn list_banned(&self) -> Result<Vec<json::ListBannedResult>> {
        self.call("listbanned", &[])
    }

    /// Clear all banned IPs.
    fn clear_banned(&self) -> Result<()> {
        self.call("clearbanned", &[])
    }

    /// Attempts to add an IP/Subnet to the banned list.
    fn add_ban(&self, subnet: &str, bantime: u64, absolute: bool) -> Result<()> {
        self.call(
            "setban",
            &[into_json(&subnet)?, into_json("add")?, into_json(&bantime)?, into_json(&absolute)?],
        )
    }

    /// Attempts to remove an IP/Subnet from the banned list.
    fn remove_ban(&self, subnet: &str) -> Result<()> {
        self.call("setban", &[into_json(&subnet)?, into_json("remove")?])
    }

    /// Disable/enable all p2p network activity.
    fn set_network_active(&self, state: bool) -> Result<bool> {
        self.call("setnetworkactive", &[into_json(&state)?])
    }

    /// Returns data about each connected network node as an array of
    /// [`PeerInfo`][]
    ///
    /// [`PeerInfo`]: net/struct.PeerInfo.html
    fn get_peer_info(&self) -> Result<Vec<json::GetPeerInfoResult>> {
        self.call("getpeerinfo", &[])
    }

    /// Requests that a ping be sent to all other nodes, to measure ping
    /// time.
    ///
    /// Results provided in `getpeerinfo`, `pingtime` and `pingwait` fields
    /// are decimal seconds.
    ///
    /// Ping command is handled in queue with all other commands, so it
    /// measures processing backlog, not just network ping.
    fn ping(&self) -> Result<()> {
        self.call("ping", &[])
    }

    fn send_raw_transaction<R: RawTx>(&self, tx: R) -> Result<TxHash> {
        self.call("sendrawtransaction", &[tx.raw_hex().into()])
    }

    /// Returns statistics about the unspent transaction output set.
    /// Note this call may take some time if you are not using coinstatsindex.
    fn get_tx_out_set_info(
        &self,
        hash_type: Option<json::TxOutSetHashType>,
        hash_or_height: Option<json::HashOrHeight>,
        use_index: Option<bool>,
    ) -> Result<json::GetTxOutSetInfoResult> {
        let mut args =
            [opt_into_json(hash_type)?, opt_into_json(hash_or_height)?, opt_into_json(use_index)?];
        self.call("gettxoutsetinfo", handle_defaults(&mut args, &[null(), null(), null()]))
    }

    /// Returns information about network traffic, including bytes in, bytes out,
    /// and current time.
    fn get_net_totals(&self) -> Result<json::GetNetTotalsResult> {
        self.call("getnettotals", &[])
    }

    /// Returns the estimated network hashes per second based on the last n blocks.
    fn get_network_hash_ps(&self, nblocks: Option<u64>, height: Option<u64>) -> Result<f64> {
        let mut args = [opt_into_json(nblocks)?, opt_into_json(height)?];
        self.call("getnetworkhashps", handle_defaults(&mut args, &[null(), null()]))
    }

    /// Returns the total uptime of the server in seconds
    fn uptime(&self) -> Result<u64> {
        self.call("uptime", &[])
    }

    /// Submit a block
    fn submit_block(&self, block: &Block) -> Result<()> {
        let mut buf = Vec::new();
        block.write(&mut buf)?;
        let block_hex: String = hex::encode(buf);
        self.submit_block_hex(&block_hex)
    }

    /// Submit a raw block
    fn submit_block_bytes(&self, block_bytes: &[u8]) -> Result<()> {
        let block_hex: String = hex::encode(block_bytes);
        self.submit_block_hex(&block_hex)
    }

    /// Submit a block as a hex string
    fn submit_block_hex(&self, block_hex: &str) -> Result<()> {
        match self.call("submitblock", &[into_json(&block_hex)?]) {
            Ok(serde_json::Value::Null) => Ok(()),
            Ok(res) => Err(Error::ReturnedError(res.to_string())),
            Err(err) => Err(err.into()),
        }
    }
}

/// Client implements a JSON-RPC client for the Bitcoin Core daemon or compatible APIs.
pub struct Client {
    client: jsonrpc::client::Client,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bitcoincore_rpc::Client({:?})", self.client)
    }
}

impl Client {
    /// Creates a client to a bitcoind JSON-RPC server.
    ///
    /// Can only return [Err] when using cookie authentication.
    pub fn new(url: &str, auth: Auth) -> Result<Self> {
        let (user, pass) = auth.get_user_pass()?;
        jsonrpc::client::Client::simple_http(url, user, pass)
            .map(|client| Client {
                client,
            })
            .map_err(|e| super::error::Error::JsonRpc(e.into()))
    }

    /// Create a new Client using the given [jsonrpc::Client].
    pub fn from_jsonrpc(client: jsonrpc::client::Client) -> Client {
        Client {
            client,
        }
    }

    /// Get the underlying JSONRPC client.
    pub fn get_jsonrpc_client(&self) -> &jsonrpc::client::Client {
        &self.client
    }
}

impl RpcApi for Client {
    /// Call an `cmd` rpc with given `args` list
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        let raw_args: Vec<_> = args
            .iter()
            .map(|a| {
                let json_string = serde_json::to_string(a)?;
                serde_json::value::RawValue::from_string(json_string) // we can't use to_raw_value here due to compat with Rust 1.29
            })
            .map(|a| a.map_err(|e| Error::Json(e)))
            .collect::<Result<Vec<_>>>()?;
        let req = self.client.build_request(&cmd, &raw_args);
        if log_enabled!(Debug) {
            debug!(target: "bitcoincore_rpc", "JSON-RPC request: {} {}", cmd, serde_json::Value::from(args));
        }

        let resp = self.client.send_request(req).map_err(Error::from);
        log_response(cmd, &resp);
        Ok(resp?.result()?)
    }
}

fn log_response(cmd: &str, resp: &Result<jsonrpc::Response>) {
    if log_enabled!(Warn) || log_enabled!(Debug) || log_enabled!(Trace) {
        match resp {
            Err(ref e) => {
                if log_enabled!(Debug) {
                    debug!(target: "bitcoincore_rpc", "JSON-RPC failed parsing reply of {}: {:?}", cmd, e);
                }
            }
            Ok(ref resp) => {
                if let Some(ref e) = resp.error {
                    if log_enabled!(Debug) {
                        debug!(target: "bitcoincore_rpc", "JSON-RPC error for {}: {:?}", cmd, e);
                    }
                } else if log_enabled!(Trace) {
                    // we can't use to_raw_value here due to compat with Rust 1.29
                    let def = serde_json::value::RawValue::from_string(
                        serde_json::Value::Null.to_string(),
                    )
                    .unwrap();
                    let result = resp.result.as_ref().unwrap_or(&def);
                    trace!(target: "bitcoincore_rpc", "JSON-RPC response for {}: {}", cmd, result);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_raw_tx() {
        let client = Client::new("http://localhost/".into(), Auth::None).unwrap();
        assert!(client.send_raw_transaction("deadbeef").is_err());
        assert!(client.send_raw_transaction("deadbeef".to_owned()).is_err());
    }

    fn test_handle_defaults_inner() -> Result<()> {
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
            let mut args = [null(), into_json(1)?];
            let defaults = [];
            let res = [null(), into_json(1)?];
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

    #[test]
    fn test_handle_defaults() {
        test_handle_defaults_inner().unwrap();
    }

    #[test]
    fn auth_cookie_file_ignores_newline() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("cookie");
        std::fs::write(&path, "foo:bar\n").unwrap();
        assert_eq!(
            Auth::CookieFile(path).get_user_pass().unwrap(),
            (Some("foo".into()), Some("bar".into())),
        );
    }

    #[test]
    fn auth_cookie_file_ignores_additional_lines() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("cookie");
        std::fs::write(&path, "foo:bar\nbaz").unwrap();
        assert_eq!(
            Auth::CookieFile(path).get_user_pass().unwrap(),
            (Some("foo".into()), Some("bar".into())),
        );
    }

    #[test]
    fn auth_cookie_file_fails_if_colon_isnt_present() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("cookie");
        std::fs::write(&path, "foobar").unwrap();
        assert!(matches!(Auth::CookieFile(path).get_user_pass(), Err(Error::InvalidCookieFile)));
    }
}
