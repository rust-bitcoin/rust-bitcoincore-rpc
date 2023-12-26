//! # rust-bitcoincore-rpc integration test
//!
//! The test methods are named to mention the methods tested.
//! Individual test methods don't use any methods not tested before or
//! mentioned in the test method name.
//!
//! The goal of this test is not to test the correctness of the server, but
//! to test the serialization of arguments and deserialization of responses.
//!

#![deny(unused)]

#[macro_use]
extern crate lazy_static;

use std::str::FromStr;
use bitcoin::address::NetworkChecked;
use bitcoinsv_rpc::jsonrpc::error::Error as JsonRpcError;
use bitcoinsv_rpc::{Auth, Client, Error, RpcApi};

use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hashes::hex::FromHex;
use bitcoin::secp256k1;
use bitcoin::{Address, Amount, Network};

lazy_static! {
    static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    static ref NET: Network = Network::Regtest;
    /// A random address not owned by the node.
    static ref RANDOM_ADDRESS: Address<NetworkChecked> = Address::from_str("mgR9fN5UzZ64mSUUtk6NwxxS6kwVfoEtPG").unwrap().assume_checked();
    /// The default fee amount to use when needed.
    static ref FEE: Amount = Amount::from_btc(0.001).unwrap();
}

struct StdLogger;

impl log::Log for StdLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().contains("jsonrpc") || metadata.target().contains("bitcoincore_rpc")
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!("[{}][{}]: {}", record.level(), record.metadata().target(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: StdLogger = StdLogger;

/// Assert that the call returns a "deprecated" error.
macro_rules! assert_deprecated {
    ($call:expr) => {
        match $call.unwrap_err() {
            Error::JsonRpc(JsonRpcError::Rpc(ref e)) if e.code == -32 => {}
            e => panic!("expected deprecated error for {}, got: {}", stringify!($call), e),
        }
    };
}

/// Assert that the call returns a "method not found" error.
macro_rules! assert_not_found {
    ($call:expr) => {
        match $call.unwrap_err() {
            Error::JsonRpc(JsonRpcError::Rpc(ref e)) if e.code == -32601 => {}
            e => panic!("expected method not found error for {}, got: {}", stringify!($call), e),
        }
    };
}

/// Assert that the call returns the specified error message.
macro_rules! assert_error_message {
    ($call:expr, $code:expr, $msg:expr) => {
        match $call.unwrap_err() {
            Error::JsonRpc(JsonRpcError::Rpc(ref e))
                if e.code == $code && e.message.contains($msg) => {}
            e => panic!("expected '{}' error for {}, got: {}", $msg, stringify!($call), e),
        }
    };
}

static mut VERSION: usize = 0;
/// Get the version of the node that is running.
fn version() -> usize {
    unsafe { VERSION }
}

/// Quickly create a BTC amount.
fn get_rpc_url() -> String {
    return std::env::var("RPC_URL").expect("RPC_URL must be set");
}

fn get_auth() -> bitcoinsv_rpc::Auth {
    if let Ok(cookie) = std::env::var("RPC_COOKIE") {
        return Auth::CookieFile(cookie.into());
    } else if let Ok(user) = std::env::var("RPC_USER") {
        return Auth::UserPass(user, std::env::var("RPC_PASS").unwrap_or_default());
    } else {
        panic!("Either RPC_COOKIE or RPC_USER + RPC_PASS must be set.");
    };
}

fn new_wallet_client(wallet_name: &str) -> Client {
    let url = format!("{}{}{}", get_rpc_url(), "/wallet/", wallet_name);
    Client::new(&url, get_auth()).unwrap()
}

fn main() {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(log::LevelFilter::max())).unwrap();

    let cl = new_wallet_client("testwallet");

    test_get_network_info(&cl);
    unsafe { VERSION = cl.version().unwrap() };
    println!("Version: {}", version());

    test_get_mining_info(&cl);
    test_get_blockchain_info(&cl);
    test_generate(&cl);
    test_get_best_block_hash(&cl);
    test_get_block_count(&cl);
    test_get_block_hash(&cl);
    test_get_block(&cl);
    test_get_block_header_get_block_header_info(&cl);
    test_get_block_stats(&cl);
    test_get_difficulty(&cl);
    test_get_connection_count(&cl);
    test_get_raw_mempool(&cl);
    test_invalidate_block_reconsider_block(&cl);
    test_ping(&cl);
    test_get_peer_info(&cl);
    test_rescan_blockchain(&cl);
    test_get_tx_out_set_info(&cl);
    test_get_chain_tips(&cl);
    test_get_net_totals(&cl);
    test_get_network_hash_ps(&cl);
    test_uptime(&cl);
    test_get_mempool_info(&cl);
    //TODO verify_message(
    test_add_node(&cl);
    test_get_added_node_info(&cl);
    test_get_node_addresses(&cl);
    test_disconnect_node(&cl);
    test_add_ban(&cl);
    test_set_network_active(&cl);
    test_get_index_info(&cl);
    test_stop(cl);
}

fn test_get_network_info(cl: &Client) {
    let _ = cl.get_network_info().unwrap();
}

fn test_get_mining_info(cl: &Client) {
    let _ = cl.get_mining_info().unwrap();
}

fn test_get_blockchain_info(cl: &Client) {
    let info = cl.get_blockchain_info().unwrap();
    assert_eq!(info.chain, Network::Regtest);
}

fn test_generate(cl: &Client) {
    if version() < 180000 {
        let blocks = cl.generate(4, None).unwrap();
        assert_eq!(blocks.len(), 4);
        let blocks = cl.generate(6, Some(45)).unwrap();
        assert_eq!(blocks.len(), 6);
    } else if version() < 190000 {
        assert_deprecated!(cl.generate(5, None));
    } else if version() < 210000 {
        assert_not_found!(cl.generate(5, None));
    } else {
        // Bitcoin Core v0.21 appears to return this with a generic -1 error code,
        // rather than the expected -32601 code (RPC_METHOD_NOT_FOUND).
        assert_error_message!(cl.generate(5, None), -1, "replaced by the -generate cli option");
    }
}

fn test_get_best_block_hash(cl: &Client) {
    let _ = cl.get_best_block_hash().unwrap();
}

fn test_get_block_count(cl: &Client) {
    let height = cl.get_block_count().unwrap();
    assert!(height > 0);
}

fn test_get_block_hash(cl: &Client) {
    let h = cl.get_block_count().unwrap();
    assert_eq!(cl.get_block_hash(h).unwrap(), cl.get_best_block_hash().unwrap());
}

fn test_get_block(cl: &Client) {
    let tip = cl.get_best_block_hash().unwrap();
    let block = cl.get_block(&tip).unwrap();
    let hex = cl.get_block_hex(&tip).unwrap();
    assert_eq!(block, deserialize(&Vec::<u8>::from_hex(&hex).unwrap()).unwrap());
    assert_eq!(hex, serialize_hex(&block));

    let tip = cl.get_best_block_hash().unwrap();
    let info = cl.get_block_info(&tip).unwrap();
    assert_eq!(info.hash, tip);
    assert_eq!(info.confirmations, 1);
}

fn test_get_block_header_get_block_header_info(cl: &Client) {
    let tip = cl.get_best_block_hash().unwrap();
    let header = cl.get_block_header(&tip).unwrap();
    let info = cl.get_block_header_info(&tip).unwrap();
    assert_eq!(header.block_hash(), info.hash);
    assert_eq!(header.version, info.version);
    assert_eq!(header.merkle_root, info.merkle_root);
    assert_eq!(info.confirmations, 1);
    assert_eq!(info.next_block_hash, None);
    assert!(info.previous_block_hash.is_some());
}

fn test_get_block_stats(cl: &Client) {
    let tip = cl.get_block_count().unwrap();
    let tip_hash = cl.get_best_block_hash().unwrap();
    let header = cl.get_block_header(&tip_hash).unwrap();
    let stats = cl.get_block_stats(tip).unwrap();
    assert_eq!(header.block_hash(), stats.block_hash);
    assert_eq!(header.time, stats.time as u32);
    assert_eq!(tip, stats.height);
}

fn test_get_difficulty(cl: &Client) {
    let _ = cl.get_difficulty().unwrap();
}

fn test_get_connection_count(cl: &Client) {
    let _ = cl.get_connection_count().unwrap();
}

fn test_get_raw_mempool(cl: &Client) {
    let _ = cl.get_raw_mempool().unwrap();
}

fn test_invalidate_block_reconsider_block(cl: &Client) {
    let hash = cl.get_best_block_hash().unwrap();
    cl.invalidate_block(&hash).unwrap();
    cl.reconsider_block(&hash).unwrap();
}

fn test_ping(cl: &Client) {
    let _ = cl.ping().unwrap();
}

fn test_get_peer_info(cl: &Client) {
    let info = cl.get_peer_info().unwrap();
    if info.is_empty() {
        panic!("No peers are connected so we can't test get_peer_info");
    }
}

fn test_rescan_blockchain(cl: &Client) {
    let count = cl.get_block_count().unwrap() as usize;
    assert!(count > 21);
    let (start, stop) = cl.rescan_blockchain(Some(count - 20), Some(count - 1)).unwrap();
    assert_eq!(start, count - 20);
    assert_eq!(stop, Some(count - 1));
}

fn test_get_tx_out_set_info(cl: &Client) {
    cl.get_tx_out_set_info(None, None, None).unwrap();
}

fn test_get_chain_tips(cl: &Client) {
    let tips = cl.get_chain_tips().unwrap();
    assert_eq!(tips.len(), 1);
}

fn test_add_node(cl: &Client) {
    cl.add_node("127.0.0.1:1234").unwrap();
    assert_error_message!(cl.add_node("127.0.0.1:1234"), -23, "Error: Node already added");
    cl.remove_node("127.0.0.1:1234").unwrap();
    cl.onetry_node("127.0.0.1:1234").unwrap();
}

fn test_get_added_node_info(cl: &Client) {
    cl.add_node("127.0.0.1:1234").unwrap();
    cl.add_node("127.0.0.1:4321").unwrap();

    assert!(cl.get_added_node_info(Some("127.0.0.1:1111")).is_err());
    assert_eq!(cl.get_added_node_info(None).unwrap().len(), 2);
    assert_eq!(cl.get_added_node_info(Some("127.0.0.1:1234")).unwrap().len(), 1);
    assert_eq!(cl.get_added_node_info(Some("127.0.0.1:4321")).unwrap().len(), 1);
}

fn test_get_node_addresses(cl: &Client) {
    cl.get_node_addresses(None).unwrap();
}

fn test_disconnect_node(cl: &Client) {
    assert_error_message!(
        cl.disconnect_node("127.0.0.1:1234"),
        -29,
        "Node not found in connected nodes"
    );
    assert_error_message!(cl.disconnect_node_by_id(1), -29, "Node not found in connected nodes");
}

fn test_add_ban(cl: &Client) {
    cl.add_ban("127.0.0.1", 0, false).unwrap();
    let res = cl.list_banned().unwrap();
    assert_eq!(res.len(), 1);

    cl.remove_ban("127.0.0.1").unwrap();
    let res = cl.list_banned().unwrap();
    assert_eq!(res.len(), 0);

    cl.add_ban("127.0.0.1", 0, false).unwrap();
    let res = cl.list_banned().unwrap();
    assert_eq!(res.len(), 1);

    cl.clear_banned().unwrap();
    let res = cl.list_banned().unwrap();
    assert_eq!(res.len(), 0);

    assert_error_message!(cl.add_ban("INVALID_STRING", 0, false), -30, "Error: Invalid IP/Subnet");
}

fn test_set_network_active(cl: &Client) {
    cl.set_network_active(false).unwrap();
    cl.set_network_active(true).unwrap();
}

fn test_get_net_totals(cl: &Client) {
    cl.get_net_totals().unwrap();
}

fn test_get_network_hash_ps(cl: &Client) {
    cl.get_network_hash_ps(None, None).unwrap();
}

fn test_uptime(cl: &Client) {
    cl.uptime().unwrap();
}

fn test_get_mempool_info(cl: &Client) {
    let res = cl.get_mempool_info().unwrap();
    assert_eq!(res.size, 0);
}

fn test_get_index_info(cl: &Client) {
    if version() >= 210000 {
        let gii = cl.get_index_info().unwrap();
        assert!(gii.txindex.is_some());
        assert!(gii.coinstatsindex.is_none());
        assert!(gii.basic_block_filter_index.is_some());
    }
}

fn test_stop(cl: Client) {
    println!("Stopping: '{}'", cl.stop().unwrap());
}
