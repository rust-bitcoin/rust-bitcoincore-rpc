use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor};
use std::iter::FromIterator;
use std::path::PathBuf;
use std::{fmt, result};
use async_trait::async_trait;
use hex::{FromHex, ToHex};
use jsonrpc;
use serde;
use serde_json;
use log::Level::{Debug, Trace, Warn};
use bitcoinsv::bitcoin::{BlockHeader, FullBlockStream, Tx, TxHash, BlockHash};
use bitcoinsv::util::Amount;
use bitcoinsv_rpc_json::GetNetworkInfoResult;
use tokio::io::{AsyncRead};
use crate::error::*;
use crate::json;

const DEFAULT_TIMEOUT_SECONDS: u64 = 300;

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

#[async_trait]
pub trait RpcApi: Sized {
    /// Call a `cmd` rpc with given `args` list
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T>;

    /// Attempts to add an IP/Subnet to the banned list.
    fn add_ban(&self, subnet: &str, bantime: u64, absolute: bool) -> Result<()> {
        self.call(
            "setban",
            &[into_json(&subnet)?, into_json("add")?, into_json(&bantime)?, into_json(&absolute)?],
        )
    }

    /// Adds an address to the list of peers that the node will attempt to connect to.
    fn add_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", &[into_json(&addr)?, into_json("add")?])
    }

    /// Clear all banned IPs.
    fn clear_banned(&self) -> Result<()> {
        self.call("clearbanned", &[])
    }

    fn create_raw_transaction(
        &self,
        utxos: &[json::CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<Tx> {
        let hex: String = self.create_raw_transaction_hex(utxos, outs, locktime, replaceable)?;
        Ok(Tx::from_hex(&hex)?)
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

    fn decode_raw_transaction(&self, tx: Tx) -> Result<json::DecodeRawTransactionResult> {
        self.call("decoderawtransaction", &[into_json(tx.encode_hex::<String>())?])
    }

    /// Disconnect from the specified address.
    fn disconnect_node(&self, addr: &str) -> Result<()> {
        self.call("disconnectnode", &[into_json(&addr)?])
    }

    /// Disconnect from the specified peer using the peer_id.
    fn disconnect_node_by_id(&self, peer_id: u32) -> Result<()> {
        self.call("disconnectnode", &[into_json("")?, into_json(peer_id)?])
    }

    /// Returns information about the given added peer, or all added peers (note that onetry addnodes are not listed here).
    fn get_added_node_info(&self, node: Option<&str>) -> Result<Vec<json::GetAddedNodeInfoResult>> {
        if let Some(addr) = node {
            self.call("getaddednodeinfo", &[into_json(&addr)?])
        } else {
            self.call("getaddednodeinfo", &[])
        }
    }

    /// Returns the hash of the best (tip) block in the longest blockchain.
    fn get_best_block_hash(&self) -> Result<BlockHash> {
        self.call("getbestblockhash", &[])
    }

    /// Fetch a complete block from the node, returning a binary reader.
    ///
    /// todo: This method of using getblock over the RPC interface is a terrible way to get blocks.
    /// It will use at least three times the size of the block in RAM on the client machine.
    /// Twice to retrieve the hex representation of the block and once to deserialize that to binary.
    async fn get_block_binary(&self, hash: &BlockHash) -> Result<Box<dyn AsyncRead + Unpin + Send>> {
        let hex: String = self.call("getblock", &[into_json(hash)?, 0.into()])?;
        let buf = hex::decode(hex)?;
        return Ok(Box::new(Cursor::new(buf)));
    }

    /// Fetch a complete block from the node, returning a FullBlockStream.
    async fn get_block(&self, hash: &BlockHash) -> Result<FullBlockStream> {
        let f = FullBlockStream::new(Box::new(self.get_block_binary(hash).await.unwrap())).await?;
        Ok(f)
    }

    /// Returns the numbers of block in the 'longest" chain (the chain with the most proof of work).
    fn get_block_count(&self) -> Result<u64> {
        self.call("getblockcount", &[])
    }

    /// Get block hash at a given height.
    fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        self.call("getblockhash", &[height.into()])
    }

    /// Returns the encoded block as a hex string.
    fn get_block_hex(&self, hash: &BlockHash) -> Result<String> {
        self.call("getblock", &[into_json(hash)?, 0.into()])
    }

    /// Returns information about the block.
    fn get_block_info(&self, hash: &BlockHash) -> Result<json::GetBlockResult> {
        self.call("getblock", &[into_json(hash)?, 1.into()])
    }

    /// Returns the block header as a BlockHeader struct.
    fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader> {
        let hex: String = self.call("getblockheader", &[into_json(hash)?, 0.into()])?;
        Ok(BlockHeader::from_hex(hex)?)
    }

    /// Returns information about the block header.
    fn get_block_header_info(
        &self,
        hash: &BlockHash,
    ) -> Result<json::GetBlockHeaderResult> {
        self.call("getblockheader", &[into_json(hash)?, 1.into()])
    }

    /// Returns information about the block header, including merkle-root and coinbase tx.
    fn get_block_header_info_full(
        &self,
        hash: &BlockHash,
    ) -> Result<json::GetBlockHeaderResult> {
        self.call("getblockheader", &[into_json(hash)?, 2.into()])
    }

    /// Compute per block statistics for a given window.
    fn get_block_stats(&self, block_hash: &BlockHash) -> Result<json::GetBlockStatsResult> {
        self.call("getblockstats", &[into_json(block_hash)?])
    }

    fn get_block_stats_fields(
        &self,
        height: u64,
        fields: &[json::BlockStatsFields],
    ) -> Result<json::GetBlockStatsResultPartial> {
        self.call("getblockstats", &[height.into(), fields.into()])
    }

    /// Returns a data structure containing various state info regarding
    /// blockchain processing.
    fn get_blockchain_info(&self) -> Result<json::GetBlockchainInfoResult> {
        let raw: serde_json::Value = self.call("getblockchaininfo", &[])?;
        Ok(serde_json::from_value(raw)?)
    }

    /// Get information about all known tips in the block tree, including the
    /// main chain as well as stale branches.
    fn get_chain_tips(&self) -> Result<json::GetChainTipsResult> {
        self.call("getchaintips", &[])
    }

    /// Return the number of current connections to the node.
    fn get_connection_count(&self) -> Result<usize> {
        self.call("getconnectioncount", &[])
    }

    /// Returns the proof-of-work difficulty as a multiple of the minimum difficulty.
    fn get_difficulty(&self) -> Result<f64> {
        self.call("getdifficulty", &[])
    }

    /// Get mempool data for given transaction
    fn get_mempool_entry(&self, tx_hash: &TxHash) -> Result<json::GetMempoolEntryResult> {
        self.call("getmempoolentry", &[into_json(tx_hash)?])
    }

    /// Returns details on the active state of the TX memory pool
    fn get_mempool_info(&self) -> Result<json::GetMempoolInfoResult> {
        self.call("getmempoolinfo", &[])
    }

    /// Returns mining-related information.
    fn get_mining_info(&self) -> Result<json::GetMiningInfoResult> {
        self.call("getmininginfo", &[])
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

    /// Get information about the network and current connections.
    fn get_network_info(&self) -> Result<json::GetNetworkInfoResult> {
        self.call("getnetworkinfo", &[])
    }

    /// Returns data about each connected network node as an array of
    /// [`PeerInfo`][]
    ///
    /// [`PeerInfo`]: net/struct.PeerInfo.html
    fn get_peer_info(&self) -> Result<Vec<json::GetPeerInfoResult>> {
        self.call("getpeerinfo", &[])
    }

    /// Get txids of all transactions in a memory pool.
    fn get_raw_mempool(&self) -> Result<Vec<TxHash>> {
        self.call("getrawmempool", &[])
    }

    /// Get details for the transactions in a memory pool.
    fn get_raw_mempool_verbose(
        &self,
    ) -> Result<HashMap<TxHash, json::GetMempoolEntryResult>> {
        self.call("getrawmempool", &[into_json(true)?])
    }

    fn get_raw_transaction(
        &self,
        tx_hash: &TxHash,
        block_hash: Option<&BlockHash>,
    ) -> Result<Tx> {
        let mut args = [into_json(tx_hash)?, into_json(false)?, opt_into_json(block_hash)?];
        let hex: String = self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))?;
        Ok(Tx::from_hex(&hex)?)
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

    /// Returns statistics about the unspent transaction output (UTXO) set.
    /// Note this call may take a considerable amount of time.
    // todo: this will possibly overrun any RPC timeouts that are set.
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

    /// List all banned IPs/Subnets.
    fn list_banned(&self) -> Result<Vec<json::ListBannedResult>> {
        self.call("listbanned", &[])
    }

    /// Mark a block as invalid. This will prevent this block and all blocks derived from this block
    /// from being considered as a valid branch of the chain.
    fn invalidate_block(&self, block_hash: &BlockHash) -> Result<()> {
        self.call("invalidateblock", &[into_json(block_hash)?])
    }

    /// Attempts to connect to a peer once without adding it to the list of peers that the node will
    /// continually try to connect to. See also add_node() and remove_node().
    fn onetry_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", &[into_json(&addr)?, into_json("onetry")?])
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

    /// Mark a block as valid. This will enable this block, and potentially all blocks derived from
    /// this block, to be considered as a valid branch of the chain. Note that the node will not
    /// switch to this chain if it is already on a better one. This cancels the effect of
    /// invalidate_block().
    fn reconsider_block(&self, block_hash: &BlockHash) -> Result<()> {
        self.call("reconsiderblock", &[into_json(block_hash)?])
    }

    /// Remove an IP/Subnet from the banned list.
    fn remove_ban(&self, subnet: &str) -> Result<()> {
        self.call("setban", &[into_json(&subnet)?, into_json("remove")?])
    }

    /// Removes an address from the list of peers that the node will attempt to connect to.
    fn remove_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", &[into_json(&addr)?, into_json("remove")?])
    }

    fn send_raw_transaction(&self, tx: Tx) -> Result<TxHash> {
        self.call("sendrawtransaction", &[into_json(tx.encode_hex::<String>())?])
    }

    /// Disable/enable all p2p network activity.
    fn set_network_active(&self, state: bool) -> Result<bool> {
        self.call("setnetworkactive", &[into_json(&state)?])
    }

    /// Stop the node.
    fn stop(&self) -> Result<String> {
        self.call("stop", &[])
    }

    /// Returns the total uptime of the server in seconds
    fn uptime(&self) -> Result<u64> {
        self.call("uptime", &[])
    }

    fn version(&self) -> Result<u32> {
        let res: GetNetworkInfoResult = self.call("getnetworkinfo", &[])?;
        Ok(res.version)
    }
}

/// Client implements a JSON-RPC client for the Bitcoin SV daemon or compatible APIs.
pub struct Client {
    client: jsonrpc::client::Client,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bitcoinsv_rpc::Client({:?})", self.client)
    }
}

impl Client {
    pub fn new(url: &str, auth: Auth, timeout: Option<std::time::Duration>) -> Result<Self> {
        let t = timeout.unwrap_or(std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECONDS));
        let b = jsonrpc::minreq_http::MinreqHttpTransport::builder()
            .timeout(t)
            .url(url)?;
        let b = match auth {
            Auth::None => b,
            Auth::UserPass(user, pass) => b.basic_auth(user, Some(pass)),
            Auth::CookieFile(path) => {
                let line = BufReader::new(File::open(path)?)
                    .lines()
                    .next()
                    .ok_or(Error::InvalidCookieFile)??;
                let colon = line.find(':').ok_or(Error::InvalidCookieFile)?;
                b.basic_auth((&line[..colon]).parse().unwrap(), Some((&line[colon + 1..]).parse().unwrap()))
            }
        };
        Ok(Client {client: jsonrpc::client::Client::with_transport(b.build())})
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
            debug!(target: "bitcoinwv_rpc", "JSON-RPC request: {} {}", cmd, serde_json::Value::from(args));
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
                    debug!(target: "bitcoinsv_rpc", "JSON-RPC failed parsing reply of {}: {:?}", cmd, e);
                }
            }
            Ok(ref resp) => {
                if let Some(ref e) = resp.error {
                    if log_enabled!(Debug) {
                        debug!(target: "bitcoinsv_rpc", "JSON-RPC error for {}: {:?}", cmd, e);
                    }
                } else if log_enabled!(Trace) {
                    // we can't use to_raw_value here due to compat with Rust 1.29
                    let def = serde_json::value::RawValue::from_string(
                        serde_json::Value::Null.to_string(),
                    )
                    .unwrap();
                    let result = resp.result.as_ref().unwrap_or(&def);
                    trace!(target: "bitcoinsv_rpc", "JSON-RPC response for {}: {}", cmd, result);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

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
