//! # rust-dashcore-rpc integration test
//!
//! The test methods are named to mention the methods tested.
//! Individual test methods don't use any methods not tested before or
//! mentioned in the test method name.
//!
//! The goal of this test is not to test the correctness of the server, but
//! to test the serialization of arguments and deserialization of responses.
//!

#[macro_use]
extern crate lazy_static;
extern crate log;

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use log::{Log, trace};

use dashcore_rpc::{json, RawTx};
use dashcore_rpc::jsonrpc::error::Error as JsonRpcError;
use dashcore_rpc::{
    dashcore::{
        consensus::encode::{deserialize, serialize},
        hashes::hex::{FromHex},
        hashes::Hash,
        secp256k1, Address, AddressType, Amount, EcdsaSighashType, Network, OutPoint, PrivateKey,
        Script, SignedAmount, Transaction, TxIn, TxOut, Txid, Witness,
    },
    Auth, Client, Error, RpcApi,
};

use dashcore_rpc::dashcore::{BlockHash, ProTxHash, QuorumHash, ScriptBuf};
use dashcore_rpc::dashcore::address::NetworkUnchecked;
use dashcore_rpc::dashcore_rpc_json::{
    GetBlockTemplateModes, GetBlockTemplateRules, ProTxInfo, ProTxRevokeReason, QuorumType,
    ScanTxOutRequest,
};
use dashcore_rpc::json::ProTxListType;
use dashcore_rpc::json::QuorumType::LlmqTest;
use json::BlockStatsFields as BsFields;

lazy_static! {
    static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    static ref NET: Network = Network::Regtest;
    /// A random address not owned by the node.
    static ref RANDOM_ADDRESS: Address = Address::from_str("yd89z5ad98AsM6kRNJ15jveAQHTUz9AJa3")
            .unwrap()
            .require_network(*NET)
            .unwrap();
    /// The default fee amount to use when needed.
    static ref FEE: Amount = Amount::from_btc(0.001).unwrap();
    // Default name for faucet wallet
    static ref FAUCET_WALLET_NAME: &'static str = "main";
    // Default name for test wallet
    static ref TEST_WALLET_NAME: &'static str = "testwallet";
    // Default RPC url for wallet node
    static ref DEFAULT_WALLET_NODE_RPC_URL: &'static str = "http://127.0.0.1:20002";
    // Default RPC url for evo node
    static ref DEFAULT_EVO_NODE_RPC_URL: &'static str = "http://127.0.0.1:20302";
}

struct StdLogger;

impl log::Log for StdLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().contains("jsonrpc") || metadata.target().contains("dashcore_rpc") || metadata.target().contains("integration_test")
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

static mut WALLET_NODE_VERSION: usize = 0;
static mut EVO_NODE_VERSION: usize = 0;

/// Get the version of the wallet node that is running.
fn wallet_node_version() -> usize {
    unsafe { WALLET_NODE_VERSION }
}

/// Get the version of the evo node that is running.
fn evo_node_version() -> usize {
    unsafe { EVO_NODE_VERSION }
}

/// Quickly create a BTC amount.
fn btc<F: Into<f64>>(btc: F) -> Amount {
    Amount::from_btc(btc.into()).unwrap()
}

/// Quickly create a signed BTC amount.
fn sbtc<F: Into<f64>>(btc: F) -> SignedAmount {
    SignedAmount::from_btc(btc.into()).unwrap()
}

fn get_rpc_urls() -> (Option<String>, Option<String>) {
    let wallet_node_url = std::env::var("WALLET_NODE_RPC_URL")
        .ok()
        .filter(|s| !s.is_empty());

    let evo_node_rpc_url = std::env::var("EVO_NODE_RPC_URL")
        .ok()
        .filter(|s| !s.is_empty());


    (wallet_node_url, evo_node_rpc_url)
}

fn get_auth() -> (Auth, Auth) {
    let wallet_node_auth = std::env::var("WALLET_NODE_RPC_COOKIE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|cookie| Auth::CookieFile(cookie.into()))
        .unwrap_or_else(|| {
            std::env::var("WALLET_NODE_RPC_USER")
                .ok()
                .filter(|s| !s.is_empty())
                .map(|user| {
                    Auth::UserPass(
                        user,
                        std::env::var("WALLET_NODE_RPC_PASS").unwrap_or_default(),
                    )
                })
                .unwrap_or(Auth::None)
        });


    let evo_node_auth = std::env::var("EVO_NODE_RPC_COOKIE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|cookie| Auth::CookieFile(cookie.into()))
        .unwrap_or_else(|| {
            std::env::var("EVO_NODE_RPC_USER")
                .ok()
                .filter(|s| !s.is_empty())
                .map(|user| {
                    Auth::UserPass(
                        user,
                        std::env::var("EVO_NODE_RPC_PASS").unwrap_or_default()
                    )
                })
                .unwrap_or(Auth::None)
        });

    (wallet_node_auth, evo_node_auth)
}

fn main() {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(log::LevelFilter::max())).unwrap();
    dotenvy::dotenv().ok();

    let (wallet_node_auth, evo_node_auth) = get_auth();
    let (wallet_node_rpc_url, evo_node_rpc_url) = get_rpc_urls();

    let wallet_node_rpc_url = wallet_node_rpc_url.unwrap_or(DEFAULT_WALLET_NODE_RPC_URL.to_string());
    let evo_node_rpc_url = evo_node_rpc_url.unwrap_or(DEFAULT_EVO_NODE_RPC_URL.to_string());

    let wallet_node_auth_type = match &wallet_node_auth {
        Auth::UserPass(_, _) => "UserPass",
        Auth::CookieFile(_) => "CookieFile",
        Auth::None => "None"
    };

    let evo_node_auth_type = match &evo_node_auth {
        Auth::UserPass(_, _) => "UserPass",
        Auth::CookieFile(_) => "CookieFile",
        Auth::None => "None"
    };

    trace!(target: "integration_test", "Wallet node RPC URL: {}", &wallet_node_rpc_url);
    trace!(target: "integration_test", "Wallet node Auth: {:?}", wallet_node_auth_type);
    trace!(target: "integration_test", "Evo node RPC URL: {}", &evo_node_rpc_url);
    trace!(target: "integration_test", "Evo node RPC Auth: {:?}", evo_node_auth_type);

    let faucet_rpc_url = format!("{}/wallet/{}", wallet_node_rpc_url, FAUCET_WALLET_NAME.to_string());
    let wallet_rpc_url = format!("{}/wallet/{}", wallet_node_rpc_url, TEST_WALLET_NAME.to_string());
    let evo_rpc_url = format!("{}/wallet/{}", evo_node_rpc_url, TEST_WALLET_NAME.to_string());

    let faucet_client = Client::new(&faucet_rpc_url, wallet_node_auth.clone().clone()).unwrap();
    let wallet_client = Client::new(&wallet_rpc_url, wallet_node_auth).unwrap();
    let evo_client = Client::new(&evo_rpc_url, evo_node_auth).unwrap();

    test_get_network_info(&wallet_client);
    test_get_network_info(&evo_client);
    unsafe { WALLET_NODE_VERSION = wallet_client.version().unwrap() };
    unsafe { EVO_NODE_VERSION = evo_client.version().unwrap() };
    trace!(target: "integration_test", "Wallet node RPC client version: {}", wallet_node_version());
    trace!(target: "integration_test", "Evo node RPC client version: {}", evo_node_version());

    wallet_client.get_blockchain_info().unwrap();
    evo_client.get_blockchain_info().unwrap();

    // Create/Load test wallet to perform operations on RPC
    match wallet_client.load_wallet(&TEST_WALLET_NAME) {
        Err(e) => {
            match e {
                dashcore_rpc::Error::JsonRpc(JsonRpcError::Rpc(ref e)) if e.code == -18 => {
                    wallet_client.create_wallet(&TEST_WALLET_NAME, None, None, None, None).unwrap();
                    trace!(target: "integration_test", "Wallet \"{}\" created", TEST_WALLET_NAME.to_string());
                },
                dashcore_rpc::Error::JsonRpc(JsonRpcError::Rpc(ref e)) if e.code == -35 => {
                    trace!(target: "integration_test", "Wallet \"{}\" already loaded", TEST_WALLET_NAME.to_string());
                }
                _ => {
                    panic!("Error loading wallet: {:?}", e);
                }
            }
        },
        Ok(_) => {
            trace!(target: "integration_test", "Loaded wallet \"{}\"", TEST_WALLET_NAME.to_string());
        }
    }

    // Fund test wallet
    let test_wallet_address = wallet_client.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();

    faucet_client.send_to_address(&test_wallet_address, btc(100.0), None, None, None, None, None, None, None, None).unwrap();

    let balance = wallet_client.get_balance(None, None).unwrap();
    trace!(target: "integration_test", "Funded wallet \"{}\". Total balance: {}", TEST_WALLET_NAME.to_string(), balance);
    faucet_client.generate_to_address(8, &test_wallet_address).unwrap();
    test_wallet_node_endpoints(&wallet_client);
    test_evo_node_endpoints(&evo_client, &wallet_client);


    return;

    // //TODO import_multi(
    // //TODO verify_message(
    // //TODO wait_for_new_block(&self, timeout: u64) -> Result<json::BlockRef> {
    // //TODO wait_for_block(
    // //TODO get_descriptor_info(&self, desc: &str) -> Result<json::GetDescriptorInfoResult> {
    // //TODO derive_addresses(&self, descriptor: &str, range: Option<[u32; 2]>) -> Result<Vec<Address>> {
    // //TODO encrypt_wallet(&self, passphrase: &str) -> Result<()> {
    // //TODO get_by_id<T: queryable::Queryable<Self>>(
    // //TODO add_multisig_address(
    // //TODO load_wallet(&self, wallet: &str) -> Result<json::LoadWalletResult> {
    // //TODO unload_wallet(&self, wallet: Option<&str>) -> Result<()> {
    // //TODO backup_wallet(&self, destination: Option<&str>) -> Result<()> {
}

fn test_wallet_node_endpoints(wallet_client: &Client) {
    test_get_mining_info(wallet_client);
    test_get_blockchain_info(wallet_client);
    test_get_new_address(wallet_client);
    test_dump_private_key(wallet_client);
    // TODO: fix - looks like there's a consensus delay when things are running on network of three nodes.
    // test_get_balance_generate_to_address(wallet_client);
    test_get_balances_generate_to_address(wallet_client);
    test_get_best_block_hash(wallet_client);
    test_get_best_chain_lock(wallet_client);
    test_get_block_count(wallet_client);
    test_get_block_hash(wallet_client);
    // TODO(dashcore): - fails to parse block
    // test_get_block(wallet_client);
    test_get_block_header_get_block_header_info(wallet_client);
    test_get_block_stats(wallet_client);
    test_get_address_info(wallet_client);
    test_set_label(wallet_client);
    test_send_to_address(wallet_client);
    test_get_received_by_address(wallet_client);
    test_list_unspent(wallet_client);
    test_get_difficulty(wallet_client);
    test_get_connection_count(wallet_client);
    test_get_raw_transaction(wallet_client);
    test_get_raw_mempool(wallet_client);
    test_get_transaction(wallet_client);
    test_list_transactions(wallet_client);
    test_list_since_block(wallet_client);
    test_get_tx_out(wallet_client);
    // TODO: fix - fails because of a consensus delay when calling `generate_to_address` inside
    // test_get_tx_out_proof(wallet_client);
    test_get_mempool_entry(wallet_client);
    test_lock_unspent_unlock_unspent(wallet_client);
    // TODO: fix
    // test_get_block_filter(wallet_client);
    test_invalidate_block_reconsider_block(wallet_client);
    test_key_pool_refill(wallet_client);
    test_sign_raw_transaction_with_send_raw_transaction(wallet_client);
    test_create_raw_transaction(wallet_client);
    test_fund_raw_transaction(wallet_client);
    test_test_mempool_accept(wallet_client);
    test_wallet_create_funded_psbt(wallet_client);
    test_wallet_process_psbt(wallet_client);
    test_combine_psbt(wallet_client);
    test_finalize_psbt(wallet_client);
    test_list_received_by_address(wallet_client);
    test_scantxoutset(wallet_client);
    test_import_public_key(wallet_client);
    test_import_priv_key(wallet_client);
    test_import_address(wallet_client);
    test_import_address_script(wallet_client);
    test_estimate_smart_fee(wallet_client);
    test_ping(wallet_client);
    test_get_peer_info(wallet_client);
    test_rescan_blockchain(wallet_client);
    test_create_wallet(wallet_client);
    test_get_tx_out_set_info(wallet_client);
    test_get_chain_tips(wallet_client);
    test_get_net_totals(wallet_client);
    test_get_network_hash_ps(wallet_client);
    test_uptime(wallet_client);
    test_getblocktemplate(wallet_client);
    test_add_node(wallet_client);
    test_get_added_node_info(wallet_client);
    test_get_node_addresses(wallet_client);
    test_disconnect_node(wallet_client);
    test_add_ban(wallet_client);
    test_set_network_active(wallet_client);
}

fn test_evo_node_endpoints(evo_client: &Client, wallet_client: &Client) {
    test_get_masternode_count(evo_client);
    test_get_masternode_list(evo_client);

    // TODO: Requested wallet does not exist or is not loaded
    // test_get_masternode_outputs(evo_client);

    test_get_masternode_payments(evo_client);
    test_get_masternode_status(evo_client);
    test_get_masternode_winners(evo_client);
    test_get_quorum_list(evo_client);
    test_get_quorum_listextended(evo_client);
    test_get_quorum_info(evo_client);
    test_get_quorum_dkgstatus(evo_client);
    test_get_quorum_sign(evo_client, wallet_client);

    // TODO: fix
    // test_get_quorum_getrecsig(evo_client);

    test_get_quorum_hasrecsig(evo_client);
    test_get_quorum_isconflicting(evo_client);

    // TODO: fix - needs real protx hash
    // test_get_quorum_memberof(evo_client);
    // TODO: fix - needs real block hash
    // test_get_quorum_rotationinfo(evo_client);

    test_get_quorum_selectquorum(evo_client);

    // TODO: fix - needs real hash
    // test_get_quorum_verify(evo_client);

    test_get_bls_fromsecret(evo_client);
    test_get_bls_generate(evo_client);

    test_get_protx_diff(evo_client);
    // TODO: fix - needs real hash
    // test_get_protx_info(evo_client);

    test_get_protx_list(evo_client);
    // TODO: fix - needs real hash
    // test_get_protx_register(evo_client);
    // TODO: fix - needs real hash
    // test_get_protx_register_fund(evo_client);
    // TODO: fix - needs real hash
    // test_get_protx_register_prepare(evo_client);
    // TODO: fix - needs real hash
    // test_get_protx_register_submit(evo_client);
    // TODO: fix - needs real hash
    // test_get_protx_revoke(evo_client)
    // TODO: fix - needs real hash
    // test_get_protx_update_registrar(evo_client);
    // TODO: fix - run masternode
    // test_get_protx_update_service(evo_client);
    // TODO: fix - needs real hash
    // test_get_verifychainlock(evo_client);
    // TODO: fix - needs real hash
    // test_get_verifyislock(evo_client);
}


fn test_get_network_info(cl: &Client) {
    let _ = cl.get_network_info().unwrap();
}

fn test_get_mining_info(cl: &Client) {
    let _ = cl.get_mining_info().unwrap();
}

fn test_get_blockchain_info(cl: &Client) {
    let info = cl.get_blockchain_info().unwrap();
    assert_eq!(&info.chain, "regtest");
}

fn test_get_new_address(cl: &Client) {
    let addr = cl.get_new_address(None).unwrap()
        .require_network(*NET)
        .unwrap();
    assert_eq!(addr.address_type(), Some(AddressType::P2pkh));

    let addr = cl.get_new_address(Some("test")).unwrap()
        .require_network(*NET)
        .unwrap();
    assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
}

fn test_dump_private_key(cl: &Client) {
    let addr = cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();
    let sk = cl.dump_private_key(&addr).unwrap();
    assert_eq!(
        addr.to_string(),
        Address::p2pkh(&sk.public_key(&SECP), *NET).to_string()
    );
}

fn test_get_balance_generate_to_address(cl: &Client) {
    let initial = cl.get_balance(None, None).unwrap();

    let address = cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();

    let blocks = cl.generate_to_address(10, &address).unwrap();
    assert_eq!(blocks.len(), 10);

    let balance_after = cl.get_balance(None, None).unwrap();
    assert_ne!(balance_after, initial);
}

fn test_get_balances_generate_to_address(cl: &Client) {
    if wallet_node_version() >= 190000 {
        let initial = cl.get_balances().unwrap();

        let address = cl.get_new_address(None).unwrap()
            .require_network(*NET).unwrap();

        let blocks = cl.generate_to_address(10, &address).unwrap();
        assert_eq!(blocks.len(), 10);
        assert_ne!(cl.get_balances().unwrap(), initial);
    }
}

fn test_get_best_block_hash(cl: &Client) {
    let _ = cl.get_best_block_hash().unwrap();
}

fn test_get_best_chain_lock(cl: &Client) {
    let _ = cl.get_best_chain_lock().unwrap();
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
    assert_eq!(hex, hex::encode(serialize(&block)));

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

fn test_get_address_info(cl: &Client) {
    // TODO: check - hex is None
    // let addr = cl.get_new_address(None).unwrap()
    //     .require_network(*NET).unwrap();
    // let info = cl.get_address_info(&addr).unwrap();
    // assert!(!info.hex.unwrap().is_empty());

    let addr = cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();
    let info = cl.get_address_info(&addr).unwrap();
    assert!(info.is_mine);
}

#[allow(deprecated)]
fn test_set_label(cl: &Client) {
    let addr = cl.get_new_address(Some("label")).unwrap()
        .require_network(*NET).unwrap();
    let info = cl.get_address_info(&addr).unwrap();
    if wallet_node_version() >= 0_20_00_00 {
        assert!(info.label.is_none());
        assert_eq!(info.labels[0], json::GetAddressInfoResultLabel::Simple("label".into()));
    } else {
        assert_eq!(info.label.as_ref().unwrap(), "label");
        assert_eq!(
            info.labels[0],
            json::GetAddressInfoResultLabel::WithPurpose {
                name: "label".into(),
                purpose: json::GetAddressInfoResultLabelPurpose::Receive,
            }
        );
    }

    cl.set_label(&addr, "other").unwrap();
    let info = cl.get_address_info(&addr).unwrap();
    if wallet_node_version() >= 0_20_00_00 {
        assert!(info.label.is_none());
        assert_eq!(info.labels[0], json::GetAddressInfoResultLabel::Simple("other".into()));
    } else {
        assert_eq!(info.label.as_ref().unwrap(), "other");
        assert_eq!(
            info.labels[0],
            json::GetAddressInfoResultLabel::WithPurpose {
                name: "other".into(),
                purpose: json::GetAddressInfoResultLabelPurpose::Receive,
            }
        );
    }
}

fn test_send_to_address(cl: &Client) {
    let addr = cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();
    let est = json::EstimateMode::Conservative;
    let _ = cl.send_to_address(&addr, btc(1), Some("cc"), None, None, None, None, None, None, None).unwrap();
    let _ = cl.send_to_address(&addr, btc(1), None, Some("tt"), None, None, None, None, None, None).unwrap();
    let _ = cl.send_to_address(&addr, btc(1), None, None, Some(true), None, None, None, None, None).unwrap();
    let _ = cl.send_to_address(&addr, btc(1), None, None, None, Some(true), None, None, None, None).unwrap();
    let _ = cl.send_to_address(&addr, btc(1), None, None, None, None, Some(false), None, None, None).unwrap();
    let _ = cl.send_to_address(&addr, btc(1), None, None, None, None, None, Some(3), None, None).unwrap();
    let _ = cl.send_to_address(&addr, btc(1), None, None, None, None, None, None,Some(est), None).unwrap();
    // TODO: restore when wallet have "avoid reuse" feature enabled
    // let _ = cl.send_to_address(&addr, btc(1), None, None, None, None, None, None,None, Some(true)).unwrap();
}

fn test_get_received_by_address(cl: &Client) {
    let addr = cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();
    let _ = cl.
        send_to_address(&addr, btc(1), None, None, None, None, None, None, None, None).unwrap();
    assert_eq!(cl.get_received_by_address(&addr, Some(0)).unwrap(), btc(1));
    assert_eq!(cl.get_received_by_address(&addr, Some(1)).unwrap(), btc(0));

    // TODO: fix - looks like there's a consensus delay when things are running on network of three nodes.
    // let addr2 = cl.get_new_address(None).unwrap()
    //     .require_network(*NET).unwrap();
    // let _ = cl.generate_to_address(1, &addr2).unwrap();
    // sleep(Duration::new(30, 0));
    // assert_eq!(cl.get_received_by_address(&addr, Some(1)).unwrap(), btc(1));
    // assert_eq!(cl.get_received_by_address(&addr, None).unwrap(), btc(1));
}

fn test_list_unspent(cl: &Client) {
    let addr_unchecked = cl.get_new_address(None).unwrap();
    let addr = addr_unchecked.clone()
        .require_network(*NET).unwrap();
    let txid = cl.
        send_to_address(&addr, btc(1), None, None, None, None, None, None, None, None).unwrap();
    let unspent = cl.list_unspent(Some(0), None, Some(&[&addr]), None, None).unwrap();
    assert_eq!(unspent[0].txid, txid);
    assert_eq!(unspent[0].address.as_ref(), Some(&addr_unchecked));
    assert_eq!(unspent[0].amount, btc(1));

    let txid = cl.
        send_to_address(&addr, btc(7), None, None, None, None, None, None, None, None).unwrap();
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(7)),
        maximum_amount: Some(btc(7)),
        ..Default::default()
    };
    let unspent = cl.list_unspent(Some(0), None, Some(&[&addr]), None, Some(options)).unwrap();
    assert_eq!(unspent.len(), 1);
    assert_eq!(unspent[0].txid, txid);
    assert_eq!(unspent[0].address.as_ref(), Some(&addr_unchecked));
    assert_eq!(unspent[0].amount, btc(7));
}

fn test_get_difficulty(cl: &Client) {
    let _ = cl.get_difficulty().unwrap();
}

fn test_get_connection_count(cl: &Client) {
    let _ = cl.get_connection_count().unwrap();
}

fn test_get_raw_transaction(cl: &Client) {
    let addr = cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();
    let txid = cl.
        send_to_address(&addr, btc(1), None, None, None, None, None, None, None, None).unwrap();
    let tx = cl.get_raw_transaction(&txid, None).unwrap();
    let hex = cl.get_raw_transaction_hex(&txid, None).unwrap();
    assert_eq!(tx, deserialize(&hex::decode(&hex).unwrap()).unwrap());
    assert_eq!(hex, hex::encode(serialize(&tx)));

    let info = cl.get_raw_transaction_info(&txid, None).unwrap();
    assert_eq!(info.txid, txid);

    // TODO: fix - consensus delay in the network of three nodes does not
    //   instantly updating chain and last call to get_raw_transaction_info
    //   results in an error
    // let addr = &cl.get_new_address(None).unwrap()
    //     .require_network(*NET).unwrap();
    // let blocks = cl.generate_to_address(7, addr).unwrap();
    // let _ = cl.get_raw_transaction_info(&txid, Some(&blocks[0])).unwrap();
}

fn test_get_raw_mempool(cl: &Client) {
    let _ = cl.get_raw_mempool().unwrap();
}

fn test_get_transaction(cl: &Client) {
    let txid =
        cl.send_to_address(&RANDOM_ADDRESS, btc(1), None, None, None, None, None, None, None, None).unwrap();
    let tx = cl.get_transaction(&txid, None).unwrap();
    assert_eq!(tx.amount, sbtc(-1.0));
    assert_eq!(tx.txid, Some(txid));

    let fake = Txid::hash(&[1, 2]);
    assert!(cl.get_transaction(&fake, Some(true)).is_err());
}

fn test_list_transactions(cl: &Client) {
    let _ = cl.list_transactions(None, None, None, None).unwrap();
    let _ = cl.list_transactions(Some("l"), None, None, None).unwrap();
    let _ = cl.list_transactions(None, Some(3), None, None).unwrap();
    let _ = cl.list_transactions(None, None, Some(3), None).unwrap();
    let _ = cl.list_transactions(None, None, None, Some(true)).unwrap();
}

fn test_list_since_block(cl: &Client) {
    let r = cl.list_since_block(None, None, None, None).unwrap();
    assert_eq!(r.lastblock, cl.get_best_block_hash().unwrap());
    assert!(!r.transactions.is_empty());
}

fn test_get_tx_out(cl: &Client) {
    let txid =
        cl.send_to_address(&RANDOM_ADDRESS, btc(1), None, None, None, None, None, None, None, None).unwrap();
    let out = cl.get_tx_out(&txid, 0, Some(false)).unwrap();
    assert!(out.is_none());
    let out = cl.get_tx_out(&txid, 0, Some(true)).unwrap();
    assert!(out.is_some());
    let _ = cl.get_tx_out(&txid, 0, None).unwrap();
}

fn test_get_tx_out_proof(cl: &Client) {
    let txid1 =
        cl.send_to_address(&RANDOM_ADDRESS, btc(1), None, None, None, None, None, None, None, None).unwrap();
    let txid2 =
        cl.send_to_address(&RANDOM_ADDRESS, btc(1), None, None, None, None, None, None, None, None).unwrap();
    let addr = &cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();
    let blocks = cl.generate_to_address(7, &addr).unwrap();
    let proof = cl.get_tx_out_proof(&[txid1, txid2], Some(&blocks[0])).unwrap();
    assert!(!proof.is_empty());
}

fn test_get_mempool_entry(cl: &Client) {
    let txid =
        cl.send_to_address(&RANDOM_ADDRESS, btc(1), None, None, None, None, None, None, None, None).unwrap();
    let entry = cl.get_mempool_entry(&txid).unwrap();
    assert!(entry.spent_by.is_empty());

    let fake = Txid::hash(&[1, 2]);
    assert!(cl.get_mempool_entry(&fake).is_err());
}

fn test_lock_unspent_unlock_unspent(cl: &Client) {
    let addr = cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();
    let txid = cl.send_to_address(&addr, btc(1), None, None, None, None, None, None, None, None).unwrap();

    assert!(cl.lock_unspent(&[OutPoint::new(txid, 0)]).unwrap());
    assert!(cl.unlock_unspent(&[OutPoint::new(txid, 0)]).unwrap());

    assert!(cl.lock_unspent(&[OutPoint::new(txid, 0)]).unwrap());
    assert!(cl.unlock_unspent_all().unwrap());
}

fn test_get_block_filter(cl: &Client) {
    let addr =  &cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();
    let blocks = cl.generate_to_address(7, &addr).unwrap();
    if wallet_node_version() >= 190000 {
        let _ = cl.get_block_filter(&blocks[0]).unwrap();
    } else {
        assert_not_found!(cl.get_block_filter(&blocks[0]));
    }
}

fn test_sign_raw_transaction_with_send_raw_transaction(cl: &Client) {
    let sk = PrivateKey {
        network: Network::Regtest,
        inner: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng()),
        compressed: true,
    };
    let addr = Address::p2pkh(&sk.public_key(&SECP), Network::Regtest);

    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl.list_unspent(Some(6), None, None, None, Some(options)).unwrap();
    let unspent = unspent.into_iter().nth(0).unwrap();

    let tx = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: unspent.txid,
                vout: unspent.vout,
            },
            sequence: 0xFFFFFFFF,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: (unspent.amount - *FEE).to_sat(),
            script_pubkey: addr.script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    let input = json::SignRawTransactionInput {
        txid: unspent.txid,
        vout: unspent.vout,
        script_pub_key: unspent.script_pub_key,
        redeem_script: None,
        amount: Some(unspent.amount),
    };
    let res = cl.sign_raw_transaction_with_wallet(&tx, Some(&[input]), None).unwrap();
    assert!(res.complete);
    let txid = cl.send_raw_transaction(&res.transaction().unwrap()).unwrap();

    let tx = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xFFFFFFFF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: (unspent.amount - *FEE - *FEE).to_sat(),
            script_pubkey: RANDOM_ADDRESS.script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    let res = cl
        .sign_raw_transaction_with_key(&tx, &[sk], None, Some(EcdsaSighashType::All.into()))
        .unwrap();
    assert!(res.complete);
    let _ = cl.send_raw_transaction(&res.transaction().unwrap()).unwrap();
}

fn test_invalidate_block_reconsider_block(cl: &Client) {
    let hash = cl.get_best_block_hash().unwrap();
    cl.invalidate_block(&hash).unwrap();
    cl.reconsider_block(&hash).unwrap();
}

fn test_key_pool_refill(cl: &Client) {
    cl.key_pool_refill(Some(100)).unwrap();
    cl.key_pool_refill(None).unwrap();
}

fn test_create_raw_transaction(cl: &Client) {
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl.list_unspent(Some(6), None, None, None, Some(options)).unwrap();
    let unspent = unspent.into_iter().nth(0).unwrap();

    let input = json::CreateRawTransactionInput {
        txid: unspent.txid,
        vout: unspent.vout,
        sequence: None,
    };
    let mut output = HashMap::new();
    output.insert(RANDOM_ADDRESS.to_string(), btc(1));

    let tx =
        cl.create_raw_transaction(&[input.clone()], &output, Some(500_000)).unwrap();
    let hex = cl.create_raw_transaction_hex(&[input], &output, Some(500_000)).unwrap();
    assert_eq!(tx, deserialize(&hex::decode(&hex).unwrap()).unwrap());
    assert_eq!(hex, hex::encode(serialize(&tx)));
}

fn test_fund_raw_transaction(cl: &Client) {
    let addr = cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();
    let mut output = HashMap::new();
    output.insert(RANDOM_ADDRESS.to_string(), btc(1));

    let options = json::FundRawTransactionOptions {
        change_address: Some(addr),
        change_position: Some(0),
        include_watching: Some(true),
        lock_unspents: Some(true),
        fee_rate: Some(*FEE),
        subtract_fee_from_outputs: Some(vec![0]),
    };
    let tx = cl.create_raw_transaction_hex(&[], &output, Some(500_000)).unwrap();
    let funded = cl.fund_raw_transaction(tx, Some(&options)).unwrap();
    let _ = funded.transaction().unwrap();

    let options = json::FundRawTransactionOptions {
        change_address: None,
        change_position: Some(0),
        include_watching: Some(true),
        lock_unspents: Some(true),
        fee_rate: None,
        subtract_fee_from_outputs: Some(vec![0]),
    };
    let tx = cl.create_raw_transaction_hex(&[], &output, Some(500_000)).unwrap();
    let funded = cl.fund_raw_transaction(tx, Some(&options)).unwrap();
    let _ = funded.transaction().unwrap();
}

fn test_test_mempool_accept(cl: &Client) {
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl.list_unspent(Some(6), None, None, None, Some(options)).unwrap();
    let unspent = unspent.into_iter().nth(0).unwrap();

    let input = json::CreateRawTransactionInput {
        txid: unspent.txid,
        vout: unspent.vout,
        sequence: Some(0xFFFFFFFF),
    };
    let mut output = HashMap::new();
    output.insert(RANDOM_ADDRESS.to_string(), unspent.amount - *FEE);

    let tx =
        cl.create_raw_transaction(&[input.clone()], &output, Some(500_000)).unwrap();
    let res = cl.test_mempool_accept(&[&tx]).unwrap();
    assert!(!res[0].allowed);
    // assert!(res[0].reject_reason.is_some());
    let signed =
        cl.sign_raw_transaction_with_wallet(&tx, None, None).unwrap().transaction().unwrap();
    let res = cl.test_mempool_accept(&[&signed]).unwrap();
    assert!(res[0].allowed, "not allowed: {:?}", res[0].reject_reason);
}

fn test_wallet_create_funded_psbt(cl: &Client) {
    let addr = cl.get_new_address(None).unwrap();
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl.list_unspent(Some(6), None, None, None, Some(options)).unwrap();
    let unspent = unspent.into_iter().nth(0).unwrap();

    let input = json::CreateRawTransactionInput {
        txid: unspent.txid,
        vout: unspent.vout,
        sequence: None,
    };
    let mut output = HashMap::new();
    output.insert(RANDOM_ADDRESS.to_string(), btc(1));

    let options = json::WalletCreateFundedPsbtOptions {
        add_inputs: None,
        change_address: None,
        change_position: Some(1),
        include_watching: Some(true),
        lock_unspent: Some(true),
        fee_rate: Some(*FEE),
        subtract_fee_from_outputs: vec![0],
        conf_target: None,
        estimate_mode: None,
    };
    let _ = cl
        .wallet_create_funded_psbt(
            &[input.clone()],
            &output,
            Some(500_000),
            Some(options),
            Some(true),
        )
        .unwrap();

    let options = json::WalletCreateFundedPsbtOptions {
        add_inputs: None,
        change_address: Some(addr),
        change_position: Some(1),
        include_watching: Some(true),
        lock_unspent: Some(true),
        fee_rate: None,
        subtract_fee_from_outputs: vec![0],
        conf_target: Some(3),
        estimate_mode: Some(json::EstimateMode::Conservative),
    };
    let psbt = cl
        .wallet_create_funded_psbt(&[input], &output, Some(500_000), Some(options), Some(true))
        .unwrap();
    assert!(!psbt.psbt.is_empty());
}

fn test_wallet_process_psbt(cl: &Client) {
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl.list_unspent(Some(6), None, None, None, Some(options)).unwrap();
    let unspent = unspent.into_iter().nth(0).unwrap();
    let input = json::CreateRawTransactionInput {
        txid: unspent.txid,
        vout: unspent.vout,
        sequence: None,
    };
    let mut output = HashMap::new();
    output.insert(RANDOM_ADDRESS.to_string(), btc(1));
    let psbt = cl
        .wallet_create_funded_psbt(&[input.clone()], &output, Some(500_000), None, Some(true))
        .unwrap();

    let res = cl.wallet_process_psbt(&psbt.psbt, Some(true), None, Some(true)).unwrap();
    assert!(res.complete);
}

fn test_combine_psbt(cl: &Client) {
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl.list_unspent(Some(6), None, None, None, Some(options)).unwrap();
    let unspent = unspent.into_iter().nth(0).unwrap();
    let input = json::CreateRawTransactionInput {
        txid: unspent.txid,
        vout: unspent.vout,
        sequence: None,
    };
    let mut output = HashMap::new();
    output.insert(RANDOM_ADDRESS.to_string(), btc(1));
    let psbt1 = cl
        .wallet_create_funded_psbt(&[input.clone()], &output, Some(500_000), None, Some(true))
        .unwrap();

    let psbt = cl.combine_psbt(&[psbt1.psbt.clone(), psbt1.psbt]).unwrap();
    assert!(!psbt.is_empty());
}

fn test_finalize_psbt(cl: &Client) {
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl.list_unspent(Some(6), None, None, None, Some(options)).unwrap();
    let unspent = unspent.into_iter().nth(0).unwrap();
    let input = json::CreateRawTransactionInput {
        txid: unspent.txid,
        vout: unspent.vout,
        sequence: None,
    };
    let mut output = HashMap::new();
    output.insert(RANDOM_ADDRESS.to_string(), btc(1));
    let psbt = cl
        .wallet_create_funded_psbt(&[input.clone()], &output, Some(500_000), None, Some(true))
        .unwrap();

    let res = cl.finalize_psbt(&psbt.psbt, Some(true)).unwrap();
    assert!(!res.complete);
    //TODO(stevenroose) add sign psbt and test hex field
    //assert!(res.hex.is_some());
}

fn test_list_received_by_address(cl: &Client) {
    let addr = cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();
    let txid = cl.send_to_address(&addr, btc(1), None, None, None, None, None, None, None, None).unwrap();

    let _ = cl.list_received_by_address(Some(&addr), None, None, None, None).unwrap();
    let _ = cl.list_received_by_address(Some(&addr), None, Some(true), None, None).unwrap();
    let _ = cl.list_received_by_address(Some(&addr), None, None, Some(true), None).unwrap();
    let _ = cl.list_received_by_address(Some(&addr), None, None, None, Some(true)).unwrap();
    let _ = cl.list_received_by_address(None, Some(200), None, None, None).unwrap();

    let res = cl.list_received_by_address(Some(&addr), Some(0), None, None, None).unwrap();
    assert_eq!(res[0].txids, vec![txid]);
}

fn test_import_public_key(cl: &Client) {
    let sk = PrivateKey {
        network: Network::Regtest,
        inner: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng()),
        compressed: true,
    };
    cl.import_public_key(&sk.public_key(&SECP), None, None).unwrap();
    cl.import_public_key(&sk.public_key(&SECP), Some("l"), None).unwrap();
    cl.import_public_key(&sk.public_key(&SECP), None, Some(false)).unwrap();
}

fn test_import_priv_key(cl: &Client) {
    let sk = PrivateKey {
        network: Network::Regtest,
        inner: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng()),
        compressed: true,
    };
    cl.import_private_key(&sk, None, None).unwrap();
    cl.import_private_key(&sk, Some("l"), None).unwrap();
    cl.import_private_key(&sk, None, Some(false)).unwrap();
}

fn test_import_address(cl: &Client) {
    let sk = PrivateKey {
        network: Network::Regtest,
        inner: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng()),
        compressed: true,
    };
    let addr = Address::p2pkh(&sk.public_key(&SECP), Network::Regtest);
    cl.import_address(&addr, None, None).unwrap();
    cl.import_address(&addr, Some("l"), None).unwrap();
    cl.import_address(&addr, None, Some(false)).unwrap();
}

fn test_import_address_script(cl: &Client) {
    let sk = PrivateKey {
        network: Network::Regtest,
        inner: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng()),
        compressed: true,
    };
    let addr = Address::p2pkh(&sk.public_key(&SECP), Network::Regtest);
    cl.import_address_script(&addr.script_pubkey(), None, None, None).unwrap();
    cl.import_address_script(&addr.script_pubkey(), Some("l"), None, None).unwrap();
    cl.import_address_script(&addr.script_pubkey(), None, Some(false), None).unwrap();
    cl.import_address_script(&addr.script_pubkey(), None, None, Some(true)).unwrap();
}

fn test_estimate_smart_fee(cl: &Client) {
    let mode = json::EstimateMode::Unset;
    let res = cl.estimate_smart_fee(3, Some(mode)).unwrap();

    // With a fresh node, we can't get fee estimates.
    if let Some(errors) = res.errors {
        if errors == &["Insufficient data or no feerate found"] {
            println!("Cannot test estimate_smart_fee because no feerate found!");
            return;
        } else {
            panic!("Unexpected error(s) for estimate_smart_fee: {:?}", errors);
        }
    }

    assert!(res.fee_rate.is_some(), "no fee estimate available: {:?}", res.errors);
    assert!(res.fee_rate.unwrap() >= btc(0));
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

fn test_create_wallet(cl: &Client) {
    let wallet_names = vec!["alice", "bob", "carol", "denise", "emily"];

    struct WalletParams<'a> {
        name: &'a str,
        disable_private_keys: Option<bool>,
        blank: Option<bool>,
        passphrase: Option<&'a str>,
        avoid_reuse: Option<bool>,
    }

    let mut wallet_params = vec![
        WalletParams {
            name: wallet_names[0],
            disable_private_keys: None,
            blank: None,
            passphrase: None,
            avoid_reuse: None,
        },
        WalletParams {
            name: wallet_names[1],
            disable_private_keys: Some(true),
            blank: None,
            passphrase: None,
            avoid_reuse: None,
        },
        WalletParams {
            name: wallet_names[2],
            disable_private_keys: None,
            blank: Some(true),
            passphrase: None,
            avoid_reuse: None,
        },
    ];

    if wallet_node_version() >= 190000 {
        wallet_params.push(WalletParams {
            name: wallet_names[3],
            disable_private_keys: None,
            blank: None,
            passphrase: Some("pass"),
            avoid_reuse: None,
        });
        wallet_params.push(WalletParams {
            name: wallet_names[4],
            disable_private_keys: None,
            blank: None,
            passphrase: None,
            avoid_reuse: Some(true),
        });
    }

    let existing_wallets = cl.list_wallets().unwrap()
        .into_iter()
        .map(|w| w)
        .collect::<HashSet<String>>();

    for wallet_param in wallet_params {
        if !existing_wallets.contains(wallet_param.name) {
            let result = cl
                .create_wallet(
                    wallet_param.name,
                    wallet_param.disable_private_keys,
                    wallet_param.blank,
                    wallet_param.passphrase,
                    wallet_param.avoid_reuse,
                )
                .unwrap();

            assert_eq!(result.name, wallet_param.name);
            let expected_warning = match (wallet_param.passphrase, wallet_param.avoid_reuse) {
                (None, Some(true)) => {
                    Some("Empty string given as passphrase, wallet will not be encrypted.".to_string())
                }
                _ => Some("".to_string()),
            };
            assert_eq!(result.warning, expected_warning);
        }

        let (wallet_rpc_url, _) = get_rpc_urls();
        let (wallet_auth, _) = get_auth();

        let wallet_rpc_url = wallet_rpc_url.unwrap_or(DEFAULT_WALLET_NODE_RPC_URL.to_string());

        let wallet_client_url = format!("{}{}{}", wallet_rpc_url, "/wallet/", wallet_param.name);
        let wallet_client = Client::new(&wallet_client_url, wallet_auth).unwrap();
        let wallet_info = wallet_client.get_wallet_info().unwrap();

        assert_eq!(wallet_info.wallet_name, wallet_param.name);

        // let has_private_keys = !wallet_param.disable_private_keys.unwrap_or(false);
        // assert_eq!(wallet_info.private_keys_enabled, has_private_keys);
        // let has_hd_seed = has_private_keys && !wallet_param.blank.unwrap_or(false);
        // assert_eq!(wallet_info.hd_seed_id.is_some(), has_hd_seed);
        // let has_avoid_reuse = wallet_param.avoid_reuse.unwrap_or(false);
        // assert_eq!(wallet_info.avoid_reuse.unwrap_or(false), has_avoid_reuse);
        assert_eq!(
            wallet_info.scanning.unwrap_or(json::ScanningDetails::NotScanning(false)),
            json::ScanningDetails::NotScanning(false)
        );
    }

    let mut wallet_list = cl.list_wallets().unwrap();

    wallet_list.sort();

    // Main wallet created for tests
    assert!(wallet_list.iter().any(|w| w == &TEST_WALLET_NAME.to_string() || w == &FAUCET_WALLET_NAME.to_string()));
    wallet_list.retain(|w| w != &TEST_WALLET_NAME.to_string() && w != "" && w != &FAUCET_WALLET_NAME.to_string());

    // Created wallets
    assert!(wallet_list.iter().zip(wallet_names).all(|(a, b)| a == b));
}

fn test_get_tx_out_set_info(cl: &Client) {
    cl.get_tx_out_set_info().unwrap();
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
    let added_info = cl.get_added_node_info(None).unwrap();
    assert_eq!(added_info.len(), 1);
    cl.remove_node("127.0.0.1:1234").unwrap();
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

fn test_scantxoutset(cl: &Client) {
    let addr = cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();

    cl.generate_to_address(2, &addr).unwrap();
    let other_addr = &cl.get_new_address(None).unwrap()
        .require_network(*NET).unwrap();
    cl.generate_to_address(7, other_addr).unwrap();

    let utxos = cl
        .scan_tx_out_set_blocking(&[ScanTxOutRequest::Single(format!("addr({})", addr))])
        .unwrap();

    assert_eq!(utxos.unspents.len(), 2);
    assert_eq!(utxos.success, Some(true));
}

fn test_getblocktemplate(cl: &Client) {
    // We want to have a transaction in the mempool so the GetBlockTemplateResult
    // contains an entry in the vector of GetBlockTemplateResultTransaction.
    // Otherwise the GetBlockTemplateResultTransaction deserialization wouldn't
    // be tested.
    cl.send_to_address(&RANDOM_ADDRESS, btc(1), None, None, None, None, None, None, None, None).unwrap();

    cl.get_block_template(GetBlockTemplateModes::Template, &[GetBlockTemplateRules::SegWit], &[])
        .unwrap();

    // let pop: &Address = &RANDOM_ADDRESS;

    // cleanup mempool transaction
    cl.generate_to_address(2, &RANDOM_ADDRESS).unwrap();
}

fn test_stop(cl: &Client) {
    println!("Stopping: '{}'", cl.stop().unwrap());
}

// ---------------------- Masternode RPC tests---------------------

fn test_get_masternode_count(cl: &Client) {
    let masternode_count = cl.get_masternode_count().unwrap();
    assert!(masternode_count.total > 0);
    assert!(masternode_count.enabled > 0);
    assert!(masternode_count.total >= masternode_count.enabled);
}

fn test_get_masternode_list(cl: &Client) {
    let _masternode_list = cl.get_masternode_list(Some("json"), None).unwrap();
}

fn test_get_masternode_outputs(cl: &Client) {
    let _masternode_outputs = cl.get_masternode_outputs().unwrap();
}

fn test_get_masternode_payments(cl: &Client) {
    let masternode_payments = cl.get_masternode_payments(None, None).unwrap();
    assert!(masternode_payments[0].height > 0);
    assert!(masternode_payments[0].amount > 0);
    assert!(masternode_payments[0].masternodes[0].amount > 0);
    assert!(masternode_payments[0].masternodes[0].payees[0].amount > 0);
    assert_eq!(masternode_payments[0].amount, masternode_payments[0].masternodes[0].amount);
    assert_eq!(
        masternode_payments[0].amount,
        masternode_payments[0].masternodes[0].payees[0].amount
    );
}

fn test_get_masternode_status(cl: &Client) {
    let _masternode_status = cl.get_masternode_status().unwrap();
}

fn test_get_masternode_winners(cl: &Client) {
    let _masternode_winners = cl.get_masternode_winners(None, None).unwrap();
}

// ---------------------- Quorum RPC tests---------------------

fn test_get_quorum_list(cl: &Client) {
    let _quorum_list = cl.get_quorum_list(Some(b'1')).unwrap();
}

fn test_get_quorum_listextended(cl: &Client) {
    let _quorum_list = cl.get_quorum_listextended(None).unwrap();
    let _quorum_list = cl.get_quorum_listextended(Some(200)).unwrap();
}

fn test_get_quorum_info(cl: &Client) {
    let list = cl.get_quorum_list(Some(1)).unwrap();
    let quorum_type = list.quorums_by_type.keys().next().unwrap().to_owned();
    let quorum_hash = list.quorums_by_type.get(&quorum_type).unwrap()[0];

    let quorum_info = cl.get_quorum_info(quorum_type, &quorum_hash, None).unwrap();
    assert!(quorum_info.height > 0);
    assert!(quorum_info.members.len() >= 0);
}

fn test_get_quorum_dkgstatus(cl: &Client) {
    let _quorum_dkgstatus = cl.get_quorum_dkgstatus(None).unwrap();
    // assert!(quorum_dkgstatus.time >= 0);
    // assert!(quorum_dkgstatus.session.len() >= 0);
    // assert!(quorum_dkgstatus.quorum_connections.len() >= 0);
    // assert!(quorum_dkgstatus.minable_commitments.len() >= 0);
}

fn test_get_quorum_sign(cl: &Client, wallet_client: &Client) {
    let list = cl.get_quorum_list(Some(1)).unwrap();
    let quorum_type = list.quorums_by_type.keys().next().unwrap().to_owned();

    let _quorum_dkgstatus = cl
        .get_quorum_sign(
            quorum_type,
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "51c11d287dfa85aef3eebb5420834c8e443e01d15c0b0a8e397d67e2e51aa239",
            None,
            None,
        )
        .unwrap();
}

fn test_get_quorum_getrecsig(cl: &Client) {
    let list = cl.get_quorum_list(Some(1)).unwrap();
    let quorum_type = list.quorums_by_type.keys().next().unwrap().to_owned();

    let _quorum_getrecsig = cl
        .get_quorum_getrecsig(
            quorum_type,
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "51c11d287dfa85aef3eebb5420834c8e443e01d15c0b0a8e397d67e2e51aa239",
        )
        .unwrap();
}

fn test_get_quorum_hasrecsig(cl: &Client) {
    let _quorum_hasrecsig = cl
        .get_quorum_hasrecsig(
            LlmqTest,
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "51c11d287dfa85aef3eebb5420834c8e443e01d15c0b0a8e397d67e2e51aa239",
        )
        .unwrap();
}

fn test_get_quorum_isconflicting(cl: &Client) {
    let _quorum_isconflicting = cl
        .get_quorum_isconflicting(
            LlmqTest,
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "51c11d287dfa85aef3eebb5420834c8e443e01d15c0b0a8e397d67e2e51aa239",
        )
        .unwrap();
}

fn test_get_quorum_memberof(cl: &Client) {
    let pro_tx_hash =
        ProTxHash::from_str("39c07d2c9c6d0ead56f52726b63c15e295cb5c3ecf7fe1fefcfb23b2e3cfed1f")
            .unwrap();
    let quorum_memberof = cl.get_quorum_memberof(&pro_tx_hash, Some(1)).unwrap();
    assert!(quorum_memberof.0[0].height > 0);
}

fn test_get_quorum_rotationinfo(cl: &Client) {
    let block_hash =
        BlockHash::from_str("0000012197b7ca6360af3756c6a49c217dbbdf8b595fd55e0fcef7ffcd546044")
            .unwrap();
    let _quorum_rotationinfo = cl.get_quorum_rotationinfo(&block_hash, None, None).unwrap();
}

fn test_get_quorum_selectquorum(cl: &Client) {
    let _quorum_selectquorum = cl
        .get_quorum_selectquorum(
            LlmqTest,
            "b95205c3bba72e9edfbe7380ec91fe5a97e16a189e28f39b03c6822757ad1a34",
        )
        .unwrap();
}

fn test_get_quorum_verify(cl: &Client) {
    let _quorum_verify = cl.get_quorum_verify(
        LlmqTest,
        "2ceeaa7ff20de327ef65b14de692199d15b67b9458d0ded7d68735cce98dd039",
        "8b5174d0e95b5642ebec23c3fe8f0bbf8f6993502f4210322871bba0e818ff3b",
        "99cf2a0deb08286a2d1ffdd2564b35522fd748c8802e561abed330dea20df5cb5a5dffeddbe627ea32cb36de13d5b4a516fdfaebae9886b2f7969a5d112416cf8d1983ebcbf1463a64f7522505627e08b9c76c036616fbb1649271a2773a1653",
        Some(QuorumHash::from_str("000000583a348d1a0a5f753ef98e6a69f9bcd9b27919f10eb1a1c3edb6c79182").unwrap()),
        None,
    ).unwrap();
}

// ---------------------- BLS cl tests---------------------

fn test_get_bls_fromsecret(cl: &Client) {
    let _bls_fromsecret = cl
        .get_bls_fromsecret("52f35cd3d977a505485f2474e7e71ef3f60f859603d72ad6b0fa7f7bd163e144")
        .unwrap();
}

fn test_get_bls_generate(cl: &Client) {
    let _bls_generate = cl.get_bls_generate().unwrap();
    // assert!(bls_generate.secret[0] >= 0);
    // assert!(bls_generate.public[0] >= 0);
}

// ---------------------- ProTx cl tests---------------------

fn test_get_protx_diff(cl: &Client) {
    let _protx_diff = cl.get_protx_diff(1000, 1000).unwrap();
}

fn test_get_protx_info(cl: &Client) {
    let pro_tx_hash =
        ProTxHash::from_str("000000000c9eddd5d2a707281b7e30d5aac974dac600ff10f01937e1ca36066f")
            .unwrap();
    let protx_info = cl.get_protx_info(&pro_tx_hash).unwrap();

    match protx_info {
        ProTxInfo {
            pro_tx_hash: _,
            collateral_hash: _,
            collateral_index,
            collateral_address: _,
            operator_reward,
            state: _,
            confirmations: _,
            wallet: _,
            meta_info: _,
            ..
        } => {
            // assert!(collateral_index >= 0);
            // assert!(operator_reward >= 0);
        }
    }
}

fn test_get_protx_list(cl: &Client) {
    let _protx_list =
        cl.get_protx_list(Some(ProTxListType::Valid), Some(true), Some(1000)).unwrap();
}

fn test_get_protx_register(cl: &Client) {
    let _protx_register = cl.get_protx_register(
        "8b2eab3413abb6e04d17d1defe2b71039ba6b6f72ea1e5dab29bb10e7b745948",
        1,
        "2.3.4.5:2345",
        "yNLuVTXJbjbxgrQX5LSMi7hV19We8hT2d6",
        "88d719278eef605d9c19037366910b59bc28d437de4a8db4d76fda6d6985dbdf10404fb9bb5cd0e8c22f4a914a6c5566",
        "yNLuVTXJbjbxgrQX5LSMi7hV19We8hT2d6",
        5.0,
        "yjJJLkYDUN6X8gWjXbCoKEXoiLeKxxMMRt",
        None,
        Some(false)
    ).unwrap();
}

fn test_get_protx_register_fund(cl: &Client) {
    let _protx_register_fund = cl.get_protx_register_fund("yakx4mMRptKhgfjedNzX5FGQq7kSSBF2e7", "3.4.5.6:3456", "yURczr3qY31xkQZfFu8eZvKz19eAEPQxsd", "0e02146e9c34cfbcb3f3037574a1abb35525e2ca0c3c6901dbf82ac591e30218d1711223b7ca956edf39f3d984d06d51", "yURczr3qY31xkQZfFu8eZvKz19eAEPQxsd",
                                                          5.0, "yUYTxqjpCfAAK4vgxXtBPywRBtZqsxN7Vy", Some("yRMFHxcJ2aS2vfo5whhE2Gg73dfQVm8LAF"), Some(false)).unwrap();
}

fn test_get_protx_register_prepare(cl: &Client) {
    let owner_address = Address::<NetworkUnchecked>::from_str("yemjhGQ99V5ayJMjoyGGPtxteahii6G1Jz").unwrap()
        .require_network(*NET).unwrap();

    let voting_address = Address::<NetworkUnchecked>::from_str("yemjhGQ99V5ayJMjoyGGPtxteahii6G1Jz").unwrap()
        .require_network(*NET).unwrap();

    let payout_address = Address::<NetworkUnchecked>::from_str("yjJJLkYDUN6X8gWjXbCoKEXoiLeKxxMMRt").unwrap()
        .require_network(*NET).unwrap();

    let _protx_register_prepare = cl.get_protx_register_prepare(
        "df41e398bb245e973340d434d386f431dbd69735a575721b0b6833856e7d31ec",
        1,
        "9.8.7.6:9876",
        owner_address,
        "06849865d01e4f73a6d5a025117e48f50b897e14235800501c8bfb8a6365cc8dbf5ddb67a3635d0f1dcc7d46a7ee280c",
        voting_address,
        1.0, //1.2,
        payout_address,
        None,
    ).unwrap();
}

fn test_get_protx_register_submit(cl: &Client) {
    let _protx_register_submit = cl.get_protx_register_submit(
        "03000100012d988526d5d1efd32320023c92eff09c2963dcb021b0de9761",
        "H90IvqVtFjZkwLJb08yMEgGixs0/FpcdvwImBcir4cYLJhD3pdX+lKD2GsPl6KNxghVXNk5/HpOdBoWAHo9u++Y=",
    ).unwrap();
}

fn test_get_protx_revoke(cl: &Client) {
    let _protx_revoke = cl
        .get_protx_revoke(
            "ba1b3330e16a0876b7a186e7ceb689f03ec646e611e91d7139de021bbf13afdd",
            "4da7e1ea30fb9e55c73ad23df0b9d3d34342acb24facf4b19420e1a26ae272d1",
            ProTxRevokeReason::NotSpecified,
            None,
        )
        .unwrap();
}

fn test_get_protx_update_registrar(cl: &Client) {
    let voting_address = Address::<NetworkUnchecked>::from_str("yX2cDS4kcJ4LK4uq9Hd4TG7kURV3sGLZrw").unwrap()
        .require_network(*NET).unwrap();

    let _protx_update_registrar = cl.get_protx_update_registrar(
        "ba1b3330e16a0876b7a186e7ceb689f03ec646e611e91d7139de021bbf13afdd",
        "0e02146e9c34cfbcb3f3037574a1abb35525e2ca0c3c6901dbf82ac591e30218d1711223b7ca956edf39f3d984d06d51",
        voting_address.clone(),
        voting_address,
        None,
    ).unwrap();
}

fn test_get_protx_update_service(cl: &Client) {
    let _protx_update_service = cl
        .get_protx_update_service(
            "ba1b3330e16a0876b7a186e7ceb689f03ec646e611e91d7139de021bbf13afdd",
            "4.3.2.1:4321",
            "4da7e1ea30fb9e55c73ad23df0b9d3d34342acb24facf4b19420e1a26ae272d1",
            None,
            None,
        )
        .unwrap();
}

fn test_get_verifychainlock(cl: &Client) {
    let _verifychainlock = cl.get_verifychainlock("00000036d5c520be6e9a32d3829efc983a7b5e88052bf138f80a2b3988689a24", "97ec34efd1615b84af62495e54024880752f57790cf450ae974b80002440963592d96826e24f109e6c149411b70bb9a0035443752368590adae60365cf4251464e0423c1263e9c56a33eae9be9e9c79a117151b2173bcee93497008cace8d793", None).unwrap();
}

fn test_get_verifyislock(cl: &Client) {
    let _verifychainlock = cl.get_verifyislock("d0b1a9c70fdfff6bf7f6cbe3d1fe33a4ca44ceb17059b6381a4ac25d9c9b6495", "8b5174d0e95b5642ebec23c3fe8f0bbf8f6993502f4210322871bba0e818ff3b", "97ec34efd1615b84af62495e54024880752f57790cf450ae974b80002440963592d96826e24f109e6c149411b70bb9a0035443752368590adae60365cf4251464e0423c1263e9c56a33eae9be9e9c79a117151b2173bcee93497008cace8d793", None).unwrap();
}
