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

use bitcoin;
use bitcoincore_rpc;
#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;

use bitcoincore_rpc::json;
// use bitcoincore_rpc::reqwest::Error as JsonRpcError;
use bitcoincore_rpc::{Auth, Client, Error, RpcApi};

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1;
use bitcoin::util::hash::BitcoinHash;
use bitcoin::{
    Address, Amount, Network, OutPoint, PrivateKey, Script, SigHashType, SignedAmount, Transaction,
    TxIn, TxOut, Txid,
};

lazy_static! {
    static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    static ref NET: Network = Network::Regtest;
    /// A random address not owned by the node.
    static ref RANDOM_ADDRESS: Address = "mgR9fN5UzZ64mSUUtk6NwxxS6kwVfoEtPG".parse().unwrap();
    /// The default fee amount to use when needed.
    static ref FEE: Amount = Amount::from_btc(0.001).unwrap();
}

/// Assert that the call returns a "deprecated" error.
macro_rules! assert_deprecated {
    ($call:expr) => {
        match $call.await.unwrap_err() {
            Error::JsonRpc(e) if e.code == -32 => {}
            e => panic!(
                "expected deprecated error for {}, got: {}",
                stringify!($call),
                e
            ),
        }
    };
}

/// Assert that the call returns a "method not found" error.
macro_rules! assert_not_found {
    ($call:expr) => {
        match $call.await.unwrap_err() {
            Error::JsonRpc(e) if e.code == -32601 => {}
            e => panic!(
                "expected method not found error for {}, got: {}",
                stringify!($call),
                e
            ),
        }
    };
}

static mut VERSION: usize = 0;
/// Get the version of the node that is running.
fn version() -> usize {
    unsafe { VERSION }
}

/// Quickly create a BTC amount.
fn btc<F: Into<f64>>(btc: F) -> Amount {
    Amount::from_btc(btc.into()).unwrap()
}
/// Quickly create a signed BTC amount.
fn sbtc<F: Into<f64>>(btc: F) -> SignedAmount {
    SignedAmount::from_btc(btc.into()).unwrap()
}

fn get_rpc_url() -> String {
    return std::env::var("RPC_URL").expect("RPC_URL must be set");
}

fn get_auth() -> bitcoincore_rpc::Auth {
    if let Ok(cookie) = std::env::var("RPC_COOKIE") {
        return Auth::CookieFile(cookie.into());
    } else if let Ok(user) = std::env::var("RPC_USER") {
        return Auth::UserPass(user, std::env::var("RPC_PASS").unwrap_or_default());
    } else {
        panic!("Either RPC_COOKIE or RPC_USER + RPC_PASS must be set.");
    };
}

#[tokio::main]
async fn main() {
    let rpc_url = get_rpc_url();
    let auth = get_auth();

    let cl = Client::new(rpc_url, auth).unwrap();

    test_get_network_info(&cl).await;
    unsafe { VERSION = cl.version().await.unwrap() };
    println!("Version: {}", version());

    test_get_mining_info(&cl).await;
    test_get_blockchain_info(&cl).await;
    test_get_new_address(&cl).await;
    test_dump_private_key(&cl).await;
    test_generate(&cl).await;
    test_get_balance_generate_to_address(&cl).await;
    test_get_balances_generate_to_address(&cl).await;
    test_get_best_block_hash(&cl).await;
    test_get_block_count(&cl).await;
    test_get_block_hash(&cl).await;
    test_get_block(&cl).await;
    test_get_block_header_get_block_header_info(&cl).await;
    test_get_address_info(&cl).await;
    test_set_label(&cl).await;
    test_send_to_address(&cl).await;
    test_get_received_by_address(&cl).await;
    test_list_unspent(&cl).await;
    test_get_difficulty(&cl).await;
    test_get_connection_count(&cl).await;
    test_get_raw_transaction(&cl).await;
    test_get_raw_mempool(&cl).await;
    test_get_transaction(&cl).await;
    test_list_transactions(&cl).await;
    test_list_since_block(&cl).await;
    test_get_tx_out(&cl).await;
    test_get_tx_out_proof(&cl).await;
    test_get_mempool_entry(&cl).await;
    test_lock_unspent_unlock_unspent(&cl).await;
    test_get_block_filter(&cl).await;
    test_sign_raw_transaction_with_send_raw_transaction(&cl).await;
    test_invalidate_block_reconsider_block(&cl).await;
    test_key_pool_refill(&cl).await;
    test_create_raw_transaction(&cl).await;
    test_fund_raw_transaction(&cl).await;
    test_test_mempool_accept(&cl).await;
    test_wallet_create_funded_psbt(&cl).await;
    test_combine_psbt(&cl).await;
    test_finalize_psbt(&cl).await;
    test_list_received_by_address(&cl).await;
    test_import_public_key(&cl).await;
    test_import_priv_key(&cl).await;
    test_import_address(&cl).await;
    test_import_address_script(&cl).await;
    test_estimate_smart_fee(&cl).await;
    test_ping(&cl).await;
    test_get_peer_info(&cl).await;
    test_rescan_blockchain(&cl).await;
    test_create_wallet(&cl).await;
    test_get_tx_out_set_info(&cl).await;
    test_get_net_totals(&cl).await;
    test_get_network_hash_ps(&cl).await;
    test_uptime(&cl).await;
    //TODO import_multi(
    //TODO verify_message(
    //TODO wait_for_new_block(&self, timeout: u64) -> Result<json::BlockRef> {
    //TODO wait_for_block(
    //TODO get_descriptor_info(&self, desc: &str) -> Result<json::GetDescriptorInfoResult> {
    //TODO derive_addresses(&self, descriptor: &str, range: Option<[u32; 2]>) -> Result<Vec<Address>> {
    //TODO encrypt_wallet(&self, passphrase: &str) -> Result<()> {
    //TODO get_by_id<T: queryable::Queryable<Self>>(
    //TODO add_multisig_address(
    //TODO load_wallet(&self, wallet: &str) -> Result<json::LoadWalletResult> {
    //TODO unload_wallet(&self, wallet: Option<&str>) -> Result<()> {
    //TODO backup_wallet(&self, destination: Option<&str>) -> Result<()> {
    test_stop(cl).await;
}

async fn test_get_network_info(cl: &Client) {
    let _ = cl.get_network_info().await.unwrap();
}

async fn test_get_mining_info(cl: &Client) {
    let _ = cl.get_mining_info().await.unwrap();
}

async fn test_get_blockchain_info(cl: &Client) {
    let info = cl.get_blockchain_info().await.unwrap();
    assert_eq!(&info.chain, "regtest");
}

async fn test_get_new_address(cl: &Client) {
    let addr = cl
        .get_new_address(None, Some(json::AddressType::Legacy))
        .await
        .unwrap();
    assert_eq!(addr.address_type(), Some(bitcoin::AddressType::P2pkh));

    let addr = cl
        .get_new_address(None, Some(json::AddressType::Bech32))
        .await
        .unwrap();
    assert_eq!(addr.address_type(), Some(bitcoin::AddressType::P2wpkh));

    let addr = cl
        .get_new_address(None, Some(json::AddressType::P2shSegwit))
        .await
        .unwrap();
    assert_eq!(addr.address_type(), Some(bitcoin::AddressType::P2sh));
}

async fn test_dump_private_key(cl: &Client) {
    let addr = cl
        .get_new_address(None, Some(json::AddressType::Bech32))
        .await
        .unwrap();
    let sk = cl.dump_private_key(&addr).await.unwrap();
    assert_eq!(addr, Address::p2wpkh(&sk.public_key(&SECP), *NET));
}

async fn test_generate(cl: &Client) {
    if version() < 180000 {
        let blocks = cl.generate(4, None).await.unwrap();
        assert_eq!(blocks.len(), 4);
        let blocks = cl.generate(6, Some(45)).await.unwrap();
        assert_eq!(blocks.len(), 6);
    } else if version() < 190000 {
        assert_deprecated!(cl.generate(5, None));
    } else {
        assert_not_found!(cl.generate(5, None));
    }
}

async fn test_get_balance_generate_to_address(cl: &Client) {
    let initial = cl.get_balance(None, None).await.unwrap();

    let blocks = cl
        .generate_to_address(500, &cl.get_new_address(None, None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(blocks.len(), 500);
    assert_ne!(cl.get_balance(None, None).await.unwrap(), initial);
}

async fn test_get_balances_generate_to_address(cl: &Client) {
    if version() >= 190000 {
        let initial = cl.get_balances().await.unwrap();

        let blocks = cl
            .generate_to_address(500, &cl.get_new_address(None, None).await.unwrap())
            .await
            .unwrap();
        assert_eq!(blocks.len(), 500);
        assert_ne!(cl.get_balances().await.unwrap(), initial);
    }
}

async fn test_get_best_block_hash(cl: &Client) {
    let _ = cl.get_best_block_hash().await.unwrap();
}

async fn test_get_block_count(cl: &Client) {
    let height = cl.get_block_count().await.unwrap();
    assert!(height > 0);
}

async fn test_get_block_hash(cl: &Client) {
    let h = cl.get_block_count().await.unwrap();
    assert_eq!(
        cl.get_block_hash(h).await.unwrap(),
        cl.get_best_block_hash().await.unwrap()
    );
}

async fn test_get_block(cl: &Client) {
    let tip = cl.get_best_block_hash().await.unwrap();
    let block = cl.get_block(&tip).await.unwrap();
    let hex = cl.get_block_hex(&tip).await.unwrap();
    assert_eq!(
        block,
        deserialize(&Vec::<u8>::from_hex(&hex).unwrap()).unwrap()
    );
    assert_eq!(hex, serialize(&block).to_hex());

    let tip = cl.get_best_block_hash().await.unwrap();
    let info = cl.get_block_info(&tip).await.unwrap();
    assert_eq!(info.hash, tip);
    assert_eq!(info.confirmations, 1);
}

async fn test_get_block_header_get_block_header_info(cl: &Client) {
    let tip = cl.get_best_block_hash().await.unwrap();
    let header = cl.get_block_header(&tip).await.unwrap();
    let info = cl.get_block_header_info(&tip).await.unwrap();
    assert_eq!(header.bitcoin_hash(), info.hash);
    assert_eq!(header.version, info.version);
    assert_eq!(header.merkle_root, info.merkle_root);
    assert_eq!(info.confirmations, 1);
    assert_eq!(info.next_block_hash, None);
    assert!(info.previous_block_hash.is_some());
}

async fn test_get_address_info(cl: &Client) {
    let addr = cl
        .get_new_address(None, Some(json::AddressType::Legacy))
        .await
        .unwrap();
    let info = cl.get_address_info(&addr).await.unwrap();
    assert!(!info.is_witness.unwrap());

    let addr = cl
        .get_new_address(None, Some(json::AddressType::Bech32))
        .await
        .unwrap();
    let info = cl.get_address_info(&addr).await.unwrap();
    assert!(!info.witness_program.unwrap().is_empty());

    let addr = cl
        .get_new_address(None, Some(json::AddressType::P2shSegwit))
        .await
        .unwrap();
    let info = cl.get_address_info(&addr).await.unwrap();
    assert!(!info.hex.unwrap().is_empty());
}

async fn test_set_label(cl: &Client) {
    let addr = cl.get_new_address(Some("label"), None).await.unwrap();
    let info = cl.get_address_info(&addr).await.unwrap();
    assert_eq!(&info.label, "label");
    assert_eq!(info.labels[0].name, "label");

    cl.set_label(&addr, "other").await.unwrap();
    let info = cl.get_address_info(&addr).await.unwrap();
    assert_eq!(&info.label, "other");
    assert_eq!(info.labels[0].name, "other");
}

async fn test_send_to_address(cl: &Client) {
    let addr = cl.get_new_address(None, None).await.unwrap();
    let est = json::EstimateMode::Conservative;
    let _ = cl
        .send_to_address(&addr, btc(1), Some("cc"), None, None, None, None, None)
        .await
        .unwrap();
    let _ = cl
        .send_to_address(&addr, btc(1), None, Some("tt"), None, None, None, None)
        .await
        .unwrap();
    let _ = cl
        .send_to_address(&addr, btc(1), None, None, Some(true), None, None, None)
        .await
        .unwrap();
    let _ = cl
        .send_to_address(&addr, btc(1), None, None, None, Some(true), None, None)
        .await
        .unwrap();
    let _ = cl
        .send_to_address(&addr, btc(1), None, None, None, None, Some(3), None)
        .await
        .unwrap();
    let _ = cl
        .send_to_address(&addr, btc(1), None, None, None, None, None, Some(est))
        .await
        .unwrap();
}

async fn test_get_received_by_address(cl: &Client) {
    let addr = cl.get_new_address(None, None).await.unwrap();
    let _ = cl
        .send_to_address(&addr, btc(1), None, None, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(
        cl.get_received_by_address(&addr, Some(0)).await.unwrap(),
        btc(1)
    );
    assert_eq!(
        cl.get_received_by_address(&addr, Some(1)).await.unwrap(),
        btc(0)
    );
    let _ = cl
        .generate_to_address(7, &cl.get_new_address(None, None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(
        cl.get_received_by_address(&addr, Some(6)).await.unwrap(),
        btc(1)
    );
    assert_eq!(
        cl.get_received_by_address(&addr, None).await.unwrap(),
        btc(1)
    );
}

async fn test_list_unspent(cl: &Client) {
    let addr = cl.get_new_address(None, None).await.unwrap();
    let txid = cl
        .send_to_address(&addr, btc(1), None, None, None, None, None, None)
        .await
        .unwrap();
    let unspent = cl
        .list_unspent(Some(0), None, Some(&[&addr]), None, None)
        .await
        .unwrap();
    assert_eq!(unspent[0].txid, txid);
    assert_eq!(unspent[0].address.as_ref(), Some(&addr));
    assert_eq!(unspent[0].amount, btc(1));

    let txid = cl
        .send_to_address(&addr, btc(7), None, None, None, None, None, None)
        .await
        .unwrap();
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(7)),
        maximum_amount: Some(btc(7)),
        ..Default::default()
    };
    let unspent = cl
        .list_unspent(Some(0), None, Some(&[&addr]), None, Some(options))
        .await
        .unwrap();
    assert_eq!(unspent.len(), 1);
    assert_eq!(unspent[0].txid, txid);
    assert_eq!(unspent[0].address.as_ref(), Some(&addr));
    assert_eq!(unspent[0].amount, btc(7));
}

async fn test_get_difficulty(cl: &Client) {
    let _ = cl.get_difficulty().await.unwrap();
}

async fn test_get_connection_count(cl: &Client) {
    let _ = cl.get_connection_count().await.unwrap();
}

async fn test_get_raw_transaction(cl: &Client) {
    let addr = cl.get_new_address(None, None).await.unwrap();
    let txid = cl
        .send_to_address(&addr, btc(1), None, None, None, None, None, None)
        .await
        .unwrap();
    let tx = cl.get_raw_transaction(&txid, None).await.unwrap();
    let hex = cl.get_raw_transaction_hex(&txid, None).await.unwrap();
    assert_eq!(
        tx,
        deserialize(&Vec::<u8>::from_hex(&hex).unwrap()).unwrap()
    );
    assert_eq!(hex, serialize(&tx).to_hex());

    let info = cl.get_raw_transaction_info(&txid, None).await.unwrap();
    assert_eq!(info.txid, txid);

    let blocks = cl
        .generate_to_address(7, &cl.get_new_address(None, None).await.unwrap())
        .await
        .unwrap();
    let _ = cl
        .get_raw_transaction_info(&txid, Some(&blocks[0]))
        .await
        .unwrap();
}

async fn test_get_raw_mempool(cl: &Client) {
    let _ = cl.get_raw_mempool().await.unwrap();
}

async fn test_get_transaction(cl: &Client) {
    let txid = cl
        .send_to_address(&RANDOM_ADDRESS, btc(1), None, None, None, None, None, None)
        .await
        .unwrap();
    let tx = cl.get_transaction(&txid, None).await.unwrap();
    assert_eq!(tx.amount, sbtc(-1.0));
    assert_eq!(tx.info.txid, txid);

    let fake = Txid::hash(&[1, 2]);
    assert!(cl.get_transaction(&fake, Some(true)).await.is_err());
}

async fn test_list_transactions(cl: &Client) {
    let _ = cl.list_transactions(None, None, None, None).await.unwrap();
    let _ = cl
        .list_transactions(Some("l"), None, None, None)
        .await
        .unwrap();
    let _ = cl
        .list_transactions(None, Some(3), None, None)
        .await
        .unwrap();
    let _ = cl
        .list_transactions(None, None, Some(3), None)
        .await
        .unwrap();
    let _ = cl
        .list_transactions(None, None, None, Some(true))
        .await
        .unwrap();
}

async fn test_list_since_block(cl: &Client) {
    let r = cl.list_since_block(None, None, None, None).await.unwrap();
    assert_eq!(r.lastblock, cl.get_best_block_hash().await.unwrap());
    assert!(!r.transactions.is_empty());
}

async fn test_get_tx_out(cl: &Client) {
    let txid = cl
        .send_to_address(&RANDOM_ADDRESS, btc(1), None, None, None, None, None, None)
        .await
        .unwrap();
    let out = cl.get_tx_out(&txid, 0, Some(false)).await.unwrap();
    assert!(out.is_none());
    let out = cl.get_tx_out(&txid, 0, Some(true)).await.unwrap();
    assert!(out.is_some());
    let _ = cl.get_tx_out(&txid, 0, None).await.unwrap();
}

async fn test_get_tx_out_proof(cl: &Client) {
    let txid1 = cl
        .send_to_address(&RANDOM_ADDRESS, btc(1), None, None, None, None, None, None)
        .await
        .unwrap();
    let txid2 = cl
        .send_to_address(&RANDOM_ADDRESS, btc(1), None, None, None, None, None, None)
        .await
        .unwrap();
    let blocks = cl
        .generate_to_address(7, &cl.get_new_address(None, None).await.unwrap())
        .await
        .unwrap();
    let proof = cl
        .get_tx_out_proof(&[txid1, txid2], Some(&blocks[0]))
        .await
        .unwrap();
    assert!(!proof.is_empty());
}

async fn test_get_mempool_entry(cl: &Client) {
    let txid = cl
        .send_to_address(&RANDOM_ADDRESS, btc(1), None, None, None, None, None, None)
        .await
        .unwrap();
    let entry = cl.get_mempool_entry(&txid).await.unwrap();
    assert!(entry.spent_by.is_empty());

    let fake = Txid::hash(&[1, 2]);
    assert!(cl.get_mempool_entry(&fake).await.is_err());
}

async fn test_lock_unspent_unlock_unspent(cl: &Client) {
    let addr = cl.get_new_address(None, None).await.unwrap();
    let txid = cl
        .send_to_address(&addr, btc(1), None, None, None, None, None, None)
        .await
        .unwrap();

    assert!(cl.lock_unspent(&[OutPoint::new(txid, 0)]).await.unwrap());
    assert!(cl.unlock_unspent(&[OutPoint::new(txid, 0)]).await.unwrap());
}

async fn test_get_block_filter(cl: &Client) {
    let blocks = cl
        .generate_to_address(7, &cl.get_new_address(None, None).await.unwrap())
        .await
        .unwrap();
    if version() >= 190000 {
        let _ = cl.get_block_filter(&blocks[0]).await.unwrap();
    } else {
        assert_not_found!(cl.get_block_filter(&blocks[0]));
    }
}

async fn test_sign_raw_transaction_with_send_raw_transaction(cl: &Client) {
    let sk = PrivateKey {
        network: Network::Regtest,
        key: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng()),
        compressed: true,
    };
    let addr = Address::p2wpkh(&sk.public_key(&SECP), Network::Regtest);

    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl
        .list_unspent(Some(6), None, None, None, Some(options))
        .await
        .unwrap();
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
            script_sig: Script::new(),
            witness: Vec::new(),
        }],
        output: vec![TxOut {
            value: (unspent.amount - *FEE).as_sat(),
            script_pubkey: addr.script_pubkey(),
        }],
    };

    let input = json::SignRawTransactionInput {
        txid: unspent.txid,
        vout: unspent.vout,
        script_pub_key: unspent.script_pub_key,
        redeem_script: None,
        amount: Some(unspent.amount),
    };
    let res = cl
        .sign_raw_transaction_with_wallet(&tx, Some(&[input]), None)
        .await
        .unwrap();
    assert!(res.complete);
    let txid = cl
        .send_raw_transaction(&res.transaction().unwrap())
        .await
        .unwrap();

    let tx = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: txid,
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: 0xFFFFFFFF,
            witness: Vec::new(),
        }],
        output: vec![TxOut {
            value: (unspent.amount - *FEE - *FEE).as_sat(),
            script_pubkey: RANDOM_ADDRESS.script_pubkey(),
        }],
    };

    let res = cl
        .sign_raw_transaction_with_key(&tx, &[sk], None, Some(SigHashType::All.into()))
        .await
        .unwrap();
    assert!(res.complete);
    let _ = cl
        .send_raw_transaction(&res.transaction().unwrap())
        .await
        .unwrap();
}

async fn test_invalidate_block_reconsider_block(cl: &Client) {
    let hash = cl.get_best_block_hash().await.unwrap();
    cl.invalidate_block(&hash).await.unwrap();
    cl.reconsider_block(&hash).await.unwrap();
}

async fn test_key_pool_refill(cl: &Client) {
    cl.key_pool_refill(Some(100)).await.unwrap();
    cl.key_pool_refill(None).await.unwrap();
}

async fn test_create_raw_transaction(cl: &Client) {
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl
        .list_unspent(Some(6), None, None, None, Some(options))
        .await
        .unwrap();
    let unspent = unspent.into_iter().nth(0).unwrap();

    let input = json::CreateRawTransactionInput {
        txid: unspent.txid,
        vout: unspent.vout,
        sequence: None,
    };
    let mut output = HashMap::new();
    output.insert(RANDOM_ADDRESS.to_string(), btc(1));

    let tx = cl
        .create_raw_transaction(&[input.clone()], &output, Some(500_000), Some(true))
        .await
        .unwrap();
    let hex = cl
        .create_raw_transaction_hex(&[input], &output, Some(500_000), Some(true))
        .await
        .unwrap();
    assert_eq!(
        tx,
        deserialize(&Vec::<u8>::from_hex(&hex).unwrap()).unwrap()
    );
    assert_eq!(hex, serialize(&tx).to_hex());
}

async fn test_fund_raw_transaction(cl: &Client) {
    let addr = cl.get_new_address(None, None).await.unwrap();
    let mut output = HashMap::new();
    output.insert(RANDOM_ADDRESS.to_string(), btc(1));

    let options = json::FundRawTransactionOptions {
        change_address: Some(addr),
        change_position: Some(0),
        change_type: None,
        include_watching: Some(true),
        lock_unspents: Some(true),
        fee_rate: Some(*FEE),
        subtract_fee_from_outputs: Some(vec![0]),
        replaceable: Some(true),
        conf_target: None,
        estimate_mode: None,
    };
    let tx = cl
        .create_raw_transaction_hex(&[], &output, Some(500_000), Some(true))
        .await
        .unwrap();
    let funded = cl
        .fund_raw_transaction(tx, Some(&options), Some(false))
        .await
        .unwrap();
    let _ = funded.transaction().unwrap();

    let options = json::FundRawTransactionOptions {
        change_address: None,
        change_position: Some(0),
        change_type: Some(json::AddressType::Legacy),
        include_watching: Some(true),
        lock_unspents: Some(true),
        fee_rate: None,
        subtract_fee_from_outputs: Some(vec![0]),
        replaceable: Some(true),
        conf_target: Some(2),
        estimate_mode: Some(json::EstimateMode::Conservative),
    };
    let tx = cl
        .create_raw_transaction_hex(&[], &output, Some(500_000), Some(true))
        .await
        .unwrap();
    let funded = cl
        .fund_raw_transaction(tx, Some(&options), Some(false))
        .await
        .unwrap();
    let _ = funded.transaction().unwrap();
}

async fn test_test_mempool_accept(cl: &Client) {
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl
        .list_unspent(Some(6), None, None, None, Some(options))
        .await
        .unwrap();
    let unspent = unspent.into_iter().nth(0).unwrap();

    let input = json::CreateRawTransactionInput {
        txid: unspent.txid,
        vout: unspent.vout,
        sequence: Some(0xFFFFFFFF),
    };
    let mut output = HashMap::new();
    output.insert(RANDOM_ADDRESS.to_string(), unspent.amount - *FEE);

    let tx = cl
        .create_raw_transaction(&[input.clone()], &output, Some(500_000), Some(false))
        .await
        .unwrap();
    let res = cl.test_mempool_accept(&[&tx]).await.unwrap();
    assert!(!res[0].allowed);
    assert!(res[0].reject_reason.is_some());
    let signed = cl
        .sign_raw_transaction_with_wallet(&tx, None, None)
        .await
        .unwrap()
        .transaction()
        .unwrap();
    let res = cl.test_mempool_accept(&[&signed]).await.unwrap();
    assert!(res[0].allowed, "not allowed: {:?}", res[0].reject_reason);
}

async fn test_wallet_create_funded_psbt(cl: &Client) {
    let addr = cl.get_new_address(None, None).await.unwrap();
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl
        .list_unspent(Some(6), None, None, None, Some(options))
        .await
        .unwrap();
    let unspent = unspent.into_iter().nth(0).unwrap();

    let input = json::CreateRawTransactionInput {
        txid: unspent.txid,
        vout: unspent.vout,
        sequence: None,
    };
    let mut output = HashMap::new();
    output.insert(RANDOM_ADDRESS.to_string(), btc(1));

    let options = json::WalletCreateFundedPsbtOptions {
        change_address: None,
        change_position: Some(1),
        change_type: Some(json::AddressType::Legacy),
        include_watching: Some(true),
        lock_unspent: Some(true),
        fee_rate: Some(*FEE),
        subtract_fee_from_outputs: vec![0],
        replaceable: Some(true),
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
        .await
        .unwrap();

    let options = json::WalletCreateFundedPsbtOptions {
        change_address: Some(addr),
        change_position: Some(1),
        change_type: None,
        include_watching: Some(true),
        lock_unspent: Some(true),
        fee_rate: None,
        subtract_fee_from_outputs: vec![0],
        replaceable: Some(true),
        conf_target: Some(3),
        estimate_mode: Some(json::EstimateMode::Conservative),
    };
    let psbt = cl
        .wallet_create_funded_psbt(&[input], &output, Some(500_000), Some(options), Some(true))
        .await
        .unwrap();
    assert!(!psbt.psbt.is_empty());
}

async fn test_combine_psbt(cl: &Client) {
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl
        .list_unspent(Some(6), None, None, None, Some(options))
        .await
        .unwrap();
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
        .await
        .unwrap();

    let psbt = cl
        .combine_psbt(&[psbt1.psbt.clone(), psbt1.psbt])
        .await
        .unwrap();
    assert!(!psbt.is_empty());
}

async fn test_finalize_psbt(cl: &Client) {
    let options = json::ListUnspentQueryOptions {
        minimum_amount: Some(btc(2)),
        ..Default::default()
    };
    let unspent = cl
        .list_unspent(Some(6), None, None, None, Some(options))
        .await
        .unwrap();
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
        .await
        .unwrap();

    let res = cl.finalize_psbt(&psbt.psbt, Some(true)).await.unwrap();
    assert!(!res.complete);
    //TODO(stevenroose) add sign psbt and test hex field
    //assert!(res.hex.is_some());
}

async fn test_list_received_by_address(cl: &Client) {
    let addr = cl.get_new_address(None, None).await.unwrap();
    let txid = cl
        .send_to_address(&addr, btc(1), None, None, None, None, None, None)
        .await
        .unwrap();

    let _ = cl
        .list_received_by_address(Some(&addr), None, None, None)
        .await
        .unwrap();
    let _ = cl
        .list_received_by_address(Some(&addr), None, Some(true), None)
        .await
        .unwrap();
    let _ = cl
        .list_received_by_address(Some(&addr), None, None, Some(true))
        .await
        .unwrap();
    let _ = cl
        .list_received_by_address(None, Some(200), None, None)
        .await
        .unwrap();

    let res = cl
        .list_received_by_address(Some(&addr), Some(0), None, None)
        .await
        .unwrap();
    assert_eq!(res[0].txids, vec![txid]);
}

async fn test_import_public_key(cl: &Client) {
    let sk = PrivateKey {
        network: Network::Regtest,
        key: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng()),
        compressed: true,
    };
    cl.import_public_key(&sk.public_key(&SECP), None, None)
        .await
        .unwrap();
    cl.import_public_key(&sk.public_key(&SECP), Some("l"), None)
        .await
        .unwrap();
    cl.import_public_key(&sk.public_key(&SECP), None, Some(false))
        .await
        .unwrap();
}

async fn test_import_priv_key(cl: &Client) {
    let sk = PrivateKey {
        network: Network::Regtest,
        key: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng()),
        compressed: true,
    };
    cl.import_private_key(&sk, None, None).await.unwrap();
    cl.import_private_key(&sk, Some("l"), None).await.unwrap();
    cl.import_private_key(&sk, None, Some(false)).await.unwrap();
}

async fn test_import_address(cl: &Client) {
    let sk = PrivateKey {
        network: Network::Regtest,
        key: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng()),
        compressed: true,
    };
    let addr = Address::p2pkh(&sk.public_key(&SECP), Network::Regtest);
    cl.import_address(&addr, None, None).await.unwrap();
    cl.import_address(&addr, Some("l"), None).await.unwrap();
    cl.import_address(&addr, None, Some(false)).await.unwrap();
}

async fn test_import_address_script(cl: &Client) {
    let sk = PrivateKey {
        network: Network::Regtest,
        key: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng()),
        compressed: true,
    };
    let addr = Address::p2pkh(&sk.public_key(&SECP), Network::Regtest);
    cl.import_address_script(&addr.script_pubkey(), None, None, None)
        .await
        .unwrap();
    cl.import_address_script(&addr.script_pubkey(), Some("l"), None, None)
        .await
        .unwrap();
    cl.import_address_script(&addr.script_pubkey(), None, Some(false), None)
        .await
        .unwrap();
    cl.import_address_script(&addr.script_pubkey(), None, None, Some(true))
        .await
        .unwrap();
}

async fn test_estimate_smart_fee(cl: &Client) {
    let mode = json::EstimateMode::Unset;
    let res = cl.estimate_smart_fee(3, Some(mode)).await.unwrap();

    // With a fresh node, we can't get fee estimates.
    if let Some(errors) = res.errors {
        if errors == &["Insufficient data or no feerate found"] {
            println!("Cannot test estimate_smart_fee because no feerate found!");
            return;
        } else {
            panic!("Unexpected error(s) for estimate_smart_fee: {:?}", errors);
        }
    }

    assert!(
        res.fee_rate.is_some(),
        "no fee estimate available: {:?}",
        res.errors
    );
    assert!(res.fee_rate.unwrap() >= btc(0));
}

async fn test_ping(cl: &Client) {
    let _ = cl.ping().await.unwrap();
}

async fn test_get_peer_info(cl: &Client) {
    let info = cl.get_peer_info().await.unwrap();
    if info.is_empty() {
        panic!("No peers are connected so we can't test get_peer_info");
    }
}

async fn test_rescan_blockchain(cl: &Client) {
    let count = cl.get_block_count().await.unwrap() as usize;
    assert!(count > 21);
    let (start, stop) = cl
        .rescan_blockchain(Some(count - 20), Some(count - 1))
        .await
        .unwrap();
    assert_eq!(start, count - 20);
    assert_eq!(stop, Some(count - 1));
}

async fn test_create_wallet(cl: &Client) {
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

    if version() >= 190000 {
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

    for wallet_param in wallet_params {
        let result = cl
            .create_wallet(
                wallet_param.name,
                wallet_param.disable_private_keys,
                wallet_param.blank,
                wallet_param.passphrase,
                wallet_param.avoid_reuse,
            )
            .await
            .unwrap();

        assert_eq!(result.name, wallet_param.name);
        let expected_warning = match (wallet_param.passphrase, wallet_param.avoid_reuse) {
            (None, Some(true)) => {
                Some("Empty string given as passphrase, wallet will not be encrypted.".to_string())
            }
            _ => Some("".to_string()),
        };
        assert_eq!(result.warning, expected_warning);

        let wallet_client_url = format!("{}{}{}", get_rpc_url(), "/wallet/", wallet_param.name);
        let wallet_client = Client::new(wallet_client_url, get_auth()).unwrap();
        let wallet_info = wallet_client.get_wallet_info().await.unwrap();

        assert_eq!(wallet_info.wallet_name, wallet_param.name);

        let has_private_keys = !wallet_param.disable_private_keys.unwrap_or(false);
        assert_eq!(wallet_info.private_keys_enabled, has_private_keys);
        let has_hd_seed = has_private_keys && !wallet_param.blank.unwrap_or(false);
        assert_eq!(wallet_info.hd_seed_id.is_some(), has_hd_seed);
        let has_avoid_reuse = wallet_param.avoid_reuse.unwrap_or(false);
        assert_eq!(wallet_info.avoid_reuse.unwrap_or(false), has_avoid_reuse);
        assert_eq!(
            wallet_info
                .scanning
                .unwrap_or(json::ScanningDetails::NotScanning(false)),
            json::ScanningDetails::NotScanning(false)
        );
    }

    let mut wallet_list = cl.list_wallets().await.unwrap();

    wallet_list.sort();

    // Default wallet
    assert_eq!(wallet_list.remove(0), "");

    // Created wallets
    assert!(wallet_list.iter().zip(wallet_names).all(|(a, b)| a == b));
}

async fn test_get_tx_out_set_info(cl: &Client) {
    cl.get_tx_out_set_info().await.unwrap();
}

async fn test_get_net_totals(cl: &Client) {
    cl.get_net_totals().await.unwrap();
}

async fn test_get_network_hash_ps(cl: &Client) {
    cl.get_network_hash_ps(None, None).await.unwrap();
}

async fn test_uptime(cl: &Client) {
    cl.uptime().await.unwrap();
}

async fn test_stop(cl: Client) {
    println!("Stopping: '{}'", cl.stop().await.unwrap());
}
