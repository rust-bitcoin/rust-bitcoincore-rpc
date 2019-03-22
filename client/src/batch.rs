// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use bitcoin;
use hex;
use jsonrpc;
use serde;
use serde_json;

use bitcoin::{Address, Block, BlockHeader, Transaction};
use bitcoin_amount::Amount;
use bitcoin_hashes::sha256d;
use log::Level::Trace;
use num_bigint::BigUint;
use secp256k1::Signature;
use std::collections::HashMap;

use super::*;

/// Response handler that uses jsonrpc::Response::into_result.
fn handle_response_into<T>(resp: jsonrpc::Response) -> Result<T>
where
    T: for<'a> serde::de::Deserialize<'a>,
{
    Ok(resp.into_result()?)
}

/// Response handler that expects hex and deserializes bytes for rust-bitcoin type.
fn handle_response_hex<T>(resp: jsonrpc::Response) -> Result<T>
where
    T: for<'a> bitcoin::consensus::encode::Decodable<Cursor<&'a [u8]>>,
{
    let hex: String = resp.into_result()?;
    let bytes = hex::decode(hex)?;
    Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
}

/// Hold a delayed result for a batched request.
pub struct BatchResult<T: 'static> {
    batch: Arc<Mutex<BatchContent>>,

    index: usize,
    response_handler: &'static Fn(jsonrpc::Response) -> Result<T>,
}

impl<T> BatchResult<T> {
    /// Whether the result is ready to be taken.
    pub fn ready(&self) -> bool {
        self.batch.lock().unwrap().responses.is_some()
    }

    /// The index of this result in the batch.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Take the result after the batch was executed.
    pub fn take(self) -> Result<T> {
        // Can only be taken once because it takes `self`.

        let mut batch = self.batch.lock().unwrap();
        let resp = batch.responses.as_mut().unwrap()[self.index].take().unwrap();
        (*self.response_handler)(resp)
    }
}

/// A pending request.
struct PendingRequest(&'static str, Vec<serde_json::Value>);

/// The content of a batch.
///
/// It is taken out of the batch because the batch methods need to be able to stick references to
/// this information with the [BatchResult] return values.
struct BatchContent {
    requests: Option<Vec<PendingRequest>>,
    responses: Option<Vec<Option<jsonrpc::Response>>>,
}

/// An ongoing batch of requests.
///
/// For documentation on the methods of [Batch], see [RpcApi].
pub struct Batch {
    client: Arc<jsonrpc::client::Client>,
    content: Arc<Mutex<BatchContent>>,
}

impl Batch {
    pub(crate) fn new(client: Arc<jsonrpc::client::Client>) -> Batch {
        Batch {
            client: client,
            content: Arc::new(Mutex::new(BatchContent {
                requests: Some(vec![]),
                responses: None,
            })),
        }
    }

    /// Execute all the requests in the batch.
    ///
    /// When one request produces an error, the execution is halted.  All prior responses will be
    /// available and the [BatchExecutionResult::Err] will contain the index of the failing
    /// response.  To not break the use of the question mark operator when the extra information is
    /// not of interest, [From<BatchExecutionError>] is implemented for [Error].
    pub fn execute(self) -> Result<()> {
        // Execution can only happen once because this takes `self`.

        let mut content = self.content.lock().unwrap();
        let pending = content.requests.take().unwrap();

        let requests: Vec<jsonrpc::Request> =
            pending.iter().map(|req| self.client.build_request(req.0, &req.1)).collect();
        if log_enabled!(Trace) {
            trace!("JSON-RPC requests [batch]: {}", serde_json::to_string(&requests).unwrap());
        }

        let responses = self.client.send_batch(&requests)?;
        if log_enabled!(Trace) {
            trace!("JSON-RPC responses [batch]: {}", serde_json::to_string(&responses).unwrap());
        }

        content.responses = Some(responses);
        Ok(())
    }

    /// Add a request to the batch.
    fn add_request(&mut self, cmd: &'static str, args: &[serde_json::Value]) -> usize {
        let req = PendingRequest(cmd, args.to_vec());

        let mut content = self.content.lock().unwrap();
        let requests = content.requests.as_mut().unwrap();

        // push the new request and return its index
        requests.push(req);
        requests.len() - 1
    }

    //
    // request methods
    //

    pub fn add_multisig_address(
        &mut self,
        nrequired: usize,
        keys: Vec<json::PubKeyOrAddress>,
        label: Option<&str>,
        address_type: Option<json::AddressType>,
    ) -> Result<BatchResult<json::AddMultiSigAddressResult>> {
        let mut args = [
            into_json(nrequired)?,
            into_json(keys)?,
            opt_into_json(label)?,
            opt_into_json(address_type)?,
        ];
        let idx = self.add_request(
            "addmultisigaddress",
            handle_defaults(&mut args, &[into_json("")?, null()]),
        );

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn backup_wallet(&mut self, destination: Option<&str>) -> Result<BatchResult<()>> {
        let mut args = [opt_into_json(destination)?];
        let idx = self.add_request("backupwallet", handle_defaults(&mut args, &[null()]));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn dump_priv_key(&mut self, address: &Address) -> Result<BatchResult<String>> {
        let idx = self.add_request("dumpprivkey", &[into_json(address)?]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn encrypt_wallet(&mut self, passphrase: &str) -> Result<BatchResult<()>> {
        let idx = self.add_request("encryptwallet", &[into_json(passphrase)?]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_difficulty(&mut self) -> Result<BatchResult<BigUint>> {
        let idx = self.add_request("getdifficulty", &[]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_connection_count(&mut self) -> Result<BatchResult<usize>> {
        let idx = self.add_request("getconnectioncount", &[]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_block(&mut self, hash: &sha256d::Hash) -> Result<BatchResult<Block>> {
        let idx = self.add_request("getblock", &[into_json(hash)?, 0.into()]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_hex,
        })
    }

    pub fn get_block_hex(&mut self, hash: &sha256d::Hash) -> Result<BatchResult<String>> {
        let idx = self.add_request("getblock", &[into_json(hash)?, 0.into()]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_block_info(
        &mut self,
        hash: &sha256d::Hash,
    ) -> Result<BatchResult<json::GetBlockResult>> {
        let idx = self.add_request("getblock", &[into_json(hash)?, 1.into()]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_block_header_raw(
        &mut self,
        hash: &sha256d::Hash,
    ) -> Result<BatchResult<BlockHeader>> {
        let idx = self.add_request("getblockheader", &[into_json(hash)?, false.into()]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_hex,
        })
    }

    pub fn get_block_header_verbose(
        &mut self,
        hash: &sha256d::Hash,
    ) -> Result<BatchResult<json::GetBlockHeaderResult>> {
        let idx = self.add_request("getblockheader", &[into_json(hash)?, true.into()]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_mining_info(&mut self) -> Result<BatchResult<json::GetMiningInfoResult>> {
        let idx = self.add_request("getmininginfo", &[]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_blockchain_info(&mut self) -> Result<BatchResult<json::GetBlockchainInfoResult>> {
        let idx = self.add_request("getblockchaininfo", &[]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_block_count(&mut self) -> Result<BatchResult<u64>> {
        let idx = self.add_request("getblockcount", &[]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_best_block_hash(&mut self) -> Result<BatchResult<sha256d::Hash>> {
        let idx = self.add_request("getbestblockhash", &[]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_block_hash(&mut self, height: u64) -> Result<BatchResult<sha256d::Hash>> {
        let idx = self.add_request("getblockhash", &[height.into()]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_raw_transaction(
        &mut self,
        txid: &sha256d::Hash,
        block_hash: Option<&sha256d::Hash>,
    ) -> Result<BatchResult<Transaction>> {
        let mut args = [into_json(txid)?, into_json(false)?, opt_into_json(block_hash)?];
        let idx = self.add_request("getrawtransaction", handle_defaults(&mut args, &[null()]));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_hex,
        })
    }

    pub fn get_raw_transaction_hex(
        &mut self,
        txid: &sha256d::Hash,
        block_hash: Option<&sha256d::Hash>,
    ) -> Result<BatchResult<String>> {
        let mut args = [into_json(txid)?, into_json(false)?, opt_into_json(block_hash)?];
        let idx = self.add_request("getrawtransaction", handle_defaults(&mut args, &[null()]));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_raw_transaction_verbose(
        &mut self,
        txid: &sha256d::Hash,
        block_hash: Option<&sha256d::Hash>,
    ) -> Result<BatchResult<json::GetRawTransactionResult>> {
        let mut args = [into_json(txid)?, into_json(true)?, opt_into_json(block_hash)?];
        let idx = self.add_request("getrawtransaction", handle_defaults(&mut args, &[null()]));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_received_by_address(
        &mut self,
        address: &Address,
        minconf: Option<u32>,
    ) -> Result<BatchResult<Amount>> {
        let mut args = [into_json(address)?, opt_into_json(minconf)?];
        let idx = self.add_request("getreceivedbyaddress", handle_defaults(&mut args, &[null()]));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_transaction(
        &mut self,
        txid: &sha256d::Hash,
        include_watchonly: Option<bool>,
    ) -> Result<BatchResult<json::GetTransactionResult>> {
        let mut args = [into_json(txid)?, opt_into_json(include_watchonly)?];
        let idx = self.add_request("getrawtransaction", handle_defaults(&mut args, &[null()]));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_tx_out(
        &mut self,
        txid: &sha256d::Hash,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<BatchResult<Option<json::GetTxOutResult>>> {
        let mut args = [into_json(txid)?, into_json(vout)?, opt_into_json(include_mempool)?];
        let idx = self.add_request("gettxout", handle_defaults(&mut args, &[null()]));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn import_priv_key(
        &mut self,
        privkey: &str,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<BatchResult<()>> {
        let mut args = [into_json(privkey)?, into_json(label)?, opt_into_json(rescan)?];
        let idx = self
            .add_request("importprivkey", handle_defaults(&mut args, &[into_json("")?, null()]));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn key_pool_refill(&mut self, new_size: Option<usize>) -> Result<BatchResult<()>> {
        let mut args = [opt_into_json(new_size)?];
        let idx = self.add_request("keypoolrefill", handle_defaults(&mut args, &[null()]));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn list_unspent(
        &mut self,
        minconf: Option<usize>,
        maxconf: Option<usize>,
        addresses: Option<Vec<&Address>>,
        include_unsafe: Option<bool>,
        query_options: Option<HashMap<&str, &str>>,
    ) -> Result<BatchResult<Vec<json::ListUnspentResult>>> {
        let mut args = [
            opt_into_json(minconf)?,
            opt_into_json(maxconf)?,
            opt_into_json(addresses)?,
            opt_into_json(include_unsafe)?,
            opt_into_json(query_options)?,
        ];
        let defaults = [
            into_json(0)?,
            into_json(9999999)?,
            into_json::<&[Address]>(&[])?,
            into_json(true)?,
            null(),
        ];
        let idx = self.add_request("listunspent", handle_defaults(&mut args, &defaults));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn create_raw_transaction_hex(
        &mut self,
        utxos: &[json::CreateRawTransactionInput],
        outs: Option<&HashMap<String, f64>>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<BatchResult<String>> {
        let mut args = [
            into_json(utxos)?,
            opt_into_json(outs)?,
            opt_into_json(locktime)?,
            opt_into_json(replaceable)?,
        ];
        let defaults =
            [into_json::<&[json::CreateRawTransactionInput]>(&[])?, into_json(0i64)?, null()];
        let idx = self.add_request("createrawtransaction", handle_defaults(&mut args, &defaults));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn create_raw_transaction(
        &mut self,
        utxos: &[json::CreateRawTransactionInput],
        outs: Option<&HashMap<String, f64>>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<BatchResult<Transaction>> {
        let mut args = [
            into_json(utxos)?,
            opt_into_json(outs)?,
            opt_into_json(locktime)?,
            opt_into_json(replaceable)?,
        ];
        let defaults =
            [into_json::<&[json::CreateRawTransactionInput]>(&[])?, into_json(0i64)?, null()];
        let idx = self.add_request("createrawtransaction", handle_defaults(&mut args, &defaults));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_hex,
        })
    }

    pub fn sign_raw_transaction(
        &mut self,
        tx: json::HexBytes,
        utxos: Option<&[json::SignRawTransactionInput]>,
        private_keys: Option<&[&str]>,
        sighash_type: Option<json::SigHashType>,
    ) -> Result<BatchResult<json::SignRawTransactionResult>> {
        let mut args = [
            into_json(tx)?,
            opt_into_json(utxos)?,
            opt_into_json(private_keys)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [
            into_json::<&[json::SignRawTransactionInput]>(&[])?,
            into_json::<&[&str]>(&[])?,
            null(),
        ];
        let idx = self.add_request("signrawtransaction", handle_defaults(&mut args, &defaults));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn sign_raw_transaction_with_key(
        &mut self,
        tx: json::HexBytes,
        privkeys: &[&str],
        prevtxs: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<json::SigHashType>,
    ) -> Result<BatchResult<json::SignRawTransactionResult>> {
        let mut args = [
            into_json(tx)?,
            into_json(privkeys)?,
            opt_into_json(prevtxs)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [into_json::<&[json::SignRawTransactionInput]>(&[])?, null()];
        let idx =
            self.add_request("signrawtransactionwithkey", handle_defaults(&mut args, &defaults));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn test_mempool_accept(
        &mut self,
        rawtxs: &[&str],
    ) -> Result<BatchResult<Vec<json::TestMempoolAccept>>> {
        let idx = self.add_request("testmempoolaccept", &[into_json(rawtxs)?]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn stop(&mut self) -> Result<BatchResult<()>> {
        let idx = self.add_request("stop", &[]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn sign_raw_transaction_with_wallet(
        &mut self,
        tx: json::HexBytes,
        utxos: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<json::SigHashType>,
    ) -> Result<BatchResult<json::SignRawTransactionResult>> {
        let mut args = [into_json(tx)?, opt_into_json(utxos)?, opt_into_json(sighash_type)?];
        let defaults = [into_json::<&[json::SignRawTransactionInput]>(&[])?, null()];
        let idx =
            self.add_request("signrawtransactionwithwallet", handle_defaults(&mut args, &defaults));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn verify_message(
        &mut self,
        address: &Address,
        signature: &Signature,
        message: &str,
    ) -> Result<BatchResult<bool>> {
        let args = [into_json(address)?, into_json(signature)?, into_json(message)?];
        let idx = self.add_request("verifymessage", &args);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_new_address(
        &mut self,
        account: Option<&str>,
        address_type: Option<json::AddressType>,
    ) -> Result<BatchResult<String>> {
        let idx = self
            .add_request("getnewaddress", &[opt_into_json(account)?, opt_into_json(address_type)?]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn generate_to_address(
        &mut self,
        block_num: u64,
        address: &str,
    ) -> Result<BatchResult<Vec<sha256d::Hash>>> {
        let idx = self.add_request("generatetoaddress", &[block_num.into(), address.into()]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn generate(
        &mut self,
        block_num: u64,
        maxtries: Option<u64>,
    ) -> Result<BatchResult<Vec<sha256d::Hash>>> {
        let idx = self.add_request("generate", &[block_num.into(), opt_into_json(maxtries)?]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn invalidate_block(&mut self, block_hash: &sha256d::Hash) -> Result<BatchResult<()>> {
        let idx = self.add_request("invalidateblock", &[into_json(block_hash)?]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn send_to_address(
        &mut self,
        addr: &str,
        amount: f64,
        comment: Option<&str>,
        comment_to: Option<&str>,
        substract_fee: Option<bool>,
    ) -> Result<BatchResult<sha256d::Hash>> {
        let mut args = [
            into_json(addr)?,
            into_json(amount)?,
            opt_into_json(comment)?,
            opt_into_json(comment_to)?,
            opt_into_json(substract_fee)?,
        ];
        let idx = self.add_request(
            "sendtoaddress",
            handle_defaults(&mut args, &["".into(), "".into(), null()]),
        );

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn get_peer_info(&mut self) -> Result<BatchResult<Vec<json::GetPeerInfoResult>>> {
        let idx = self.add_request("getpeerinfo", &[]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn ping(&mut self) -> Result<BatchResult<()>> {
        let idx = self.add_request("ping", &[]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn send_raw_transaction(&mut self, tx: &str) -> Result<BatchResult<String>> {
        let idx = self.add_request("sendrawtransaction", &[into_json(tx)?]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn estimate_smartfee<E>(
        &mut self,
        conf_target: u16,
        estimate_mode: Option<json::EstimateMode>,
    ) -> Result<BatchResult<json::EstimateSmartFeeResult>> {
        let mut args = [into_json(conf_target)?, opt_into_json(estimate_mode)?];
        let idx = self.add_request("estimatesmartfee", handle_defaults(&mut args, &[null()]));

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn wait_for_new_block(&mut self, timeout: u64) -> Result<BatchResult<json::BlockRef>> {
        let idx = self.add_request("waitfornewblock", &[into_json(timeout)?]);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }

    pub fn wait_for_block(
        &mut self,
        blockhash: &sha256d::Hash,
        timeout: u64,
    ) -> Result<BatchResult<json::BlockRef>> {
        let args = [into_json(blockhash)?, into_json(timeout)?];
        let idx = self.add_request("waitforblock", &args);

        Ok(BatchResult {
            batch: self.content.clone(),
            index: idx,
            response_handler: &handle_response_into,
        })
    }
}
