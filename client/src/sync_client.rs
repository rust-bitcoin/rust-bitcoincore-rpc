
use std::sync::atomic;

use crate::bitcoin::secp256k1::ecdsa::Signature;
use crate::bitcoin::{
    self, Address, Amount, Block, OutPoint, PrivateKey, PublicKey,
    ScriptBuf, Transaction, FeeRate,
};
use crate::bitcoin::block::Header as BlockHeader;
use crate::bitcoin::psbt::PartiallySignedTransaction;
type UncheckedAddress = Address<crate::bitcoin::address::NetworkUnchecked>;

use jsonrpc::client::{List, Param, Params, Request};

use crate::{
    json, requests, AddressParam, Client, BlockRef, BlockParam, Error,
    Result, PsbtParam, SighashParam, TxParam,
};
use crate::serialize::{
    HexListSerializeWrapper, HexSerializeWrapper,
    OutPointListObjectSerializeWrapper,
    StringListSerializeWrapper, StringSerializeWrapper,
};

/// Synchronous client API.
pub trait SyncClient {
    /// The internal method to make a request.
    fn handle_request<'r, T>(&self, req: Request<'r, T>) -> Result<T>;

    /// Make a manual call.
    fn call<T: for<'a> serde::de::Deserialize<'a> + 'static>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> Result<T> {
        let params = params.iter().map(|v| Param::ByRef(v)).collect::<Vec<_>>();
        self.handle_request(
            Request {
                method: method.into(),
                params: Params::ByPosition(List::Slice(&params[..])),
                converter: &|raw| requests::converter_json(raw),
            }
        )
    }

    /// Get cached version of the version.
    fn version(&self) -> Result<usize>;

    /// Refresh the cached version by asking the server again.
    fn refresh_version(&self) -> Result<()>;

    fn get_version(&self) -> Result<usize> {
        self.handle_request(requests::version())
    }

    fn get_network_info(&self) -> Result<json::GetNetworkInfoResult> {
        self.handle_request(requests::get_network_info())
    }

    fn get_index_info(&self) -> Result<json::GetIndexInfoResult> {
        self.handle_request(requests::get_index_info())
    }

    fn add_multisig_address(
        &self,
        nrequired: usize,
        keys: &[json::PubKeyOrAddress],
        label: Option<&str>,
        address_type: Option<&json::AddressType>,
    ) -> Result<json::AddMultiSigAddressResult> {
        self.handle_request(requests::add_multisig_address(
            nrequired, &keys, label.as_ref(), address_type,
        ))
    }

    fn load_wallet(&self, wallet: &str) -> Result<json::LoadWalletResult> {
        self.handle_request(requests::load_wallet(&wallet))
    }

    fn unload_wallet(&self, wallet: Option<&str>) -> Result<json::UnloadWalletResult> {
        self.handle_request(requests::unload_wallet(wallet.as_ref()))
    }

    fn create_wallet(
        &self,
        wallet: &str,
        disable_private_keys: Option<bool>,
        blank: Option<bool>,
        passphrase: Option<&str>,
        avoid_reuse: Option<bool>,
    ) -> Result<json::LoadWalletResult> {
        self.handle_request(requests::create_wallet(
            &wallet, disable_private_keys, blank, passphrase.as_ref(), avoid_reuse,
        ))
    }

    fn list_wallets(&self) -> Result<Vec<String>> {
        self.handle_request(requests::list_wallets())
    }

    fn list_wallet_dir(&self) -> Result<Vec<String>> {
        self.handle_request(requests::list_wallet_dir())
    }

    fn get_wallet_info(&self) -> Result<json::GetWalletInfoResult> {
        self.handle_request(requests::get_wallet_info())
    }

    fn backup_wallet(&self, destination: &str) -> Result<()> {
        self.handle_request(requests::backup_wallet(&destination))
    }

    fn dump_private_key(
        &self,
        address: &(impl AddressParam + ?Sized),
    ) -> Result<PrivateKey> {
        self.handle_request(requests::dump_private_key(&StringSerializeWrapper(address)))
    }

    fn encrypt_wallet(&self, passphrase: &str) -> Result<String> {
        self.handle_request(requests::encrypt_wallet(&passphrase))
    }

    fn get_difficulty(&self) -> Result<f64> {
        self.handle_request(requests::get_difficulty())
    }

    fn get_connection_count(&self) -> Result<usize> {
        self.handle_request(requests::get_connection_count())
    }

    fn get_block(&self, hash: &bitcoin::BlockHash) -> Result<Block> {
        self.handle_request(requests::get_block(hash))
    }

    fn get_block_hex(&self, hash: &bitcoin::BlockHash) -> Result<String> {
        self.handle_request(requests::get_block_hex(hash))
    }

    fn get_block_info(&self, hash: &bitcoin::BlockHash) -> Result<json::GetBlockResult> {
        self.handle_request(requests::get_block_info(hash))
    }
    //TODO(stevenroose) add getblock_txs

    fn get_block_header(&self, hash: &bitcoin::BlockHash) -> Result<BlockHeader> {
        self.handle_request(requests::get_block_header(hash))
    }

    fn get_block_header_info(
        &self,
        hash: &bitcoin::BlockHash,
    ) -> Result<json::GetBlockHeaderResult> {
        self.handle_request(requests::get_block_header_info(hash))
    }

    fn get_mining_info(&self) -> Result<json::GetMiningInfoResult> {
        self.handle_request(requests::get_mining_info())
    }

    fn get_block_template(
        &self,
        mode: json::GetBlockTemplateModes,
        rules: &[json::GetBlockTemplateRules],
        capabilities: &[json::GetBlockTemplateCapabilities],
    ) -> Result<json::GetBlockTemplateResult> {
        self.handle_request(requests::get_block_template(&mode, &rules, &capabilities))
    }

    fn get_blockchain_info(&self) -> Result<json::GetBlockchainInfoResult> {
        self.handle_request(requests::get_blockchain_info())
    }

    fn get_block_count(&self) -> Result<u64> {
        self.handle_request(requests::get_block_count())
    }

    fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash> {
        self.handle_request(requests::get_best_block_hash())
    }

    fn get_block_hash(&self, height: u64) -> Result<bitcoin::BlockHash> {
        self.handle_request(requests::get_block_hash(height))
    }
    
    fn get_block_stats(&self, block_ref: impl BlockRef) -> Result<json::GetBlockStatsResult> {
        self.handle_request(requests::get_block_stats(&block_ref))
    }

    fn get_block_stats_fields(
        &self,
        block_ref: impl BlockRef,
        fields: &[json::BlockStatsFields],
    ) -> Result<json::GetBlockStatsResultPartial> {
        self.handle_request(requests::get_block_stats_fields(&block_ref, &fields))
    }

    fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<Transaction> {
        self.handle_request(requests::get_raw_transaction(txid, block_hash))
    }

    fn get_raw_transaction_hex(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<String> {
        self.handle_request(requests::get_raw_transaction_hex(txid, block_hash))
    }

    fn get_raw_transaction_info(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<json::GetRawTransactionResult> {
        self.handle_request(requests::get_raw_transaction_info(txid, block_hash))
    }

    fn get_block_filter(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<json::GetBlockFilterResult> {
        self.handle_request(requests::get_block_filter(block_hash))
    }

    fn get_balance(
        &self,
        minconf: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Amount> {
        self.handle_request(requests::get_balance(minconf, include_watchonly))
    }

    fn get_balances(&self) -> Result<json::GetBalancesResult> {
        self.handle_request(requests::get_balances())
    }

    fn get_received_by_address(
        &self,
        address: &(impl AddressParam + ?Sized),
        minconf: Option<u32>,
    ) -> Result<Amount> {
        self.handle_request(requests::get_received_by_address(
            &StringSerializeWrapper(address), minconf,
        ))
    }

    fn get_transaction(
        &self,
        txid: &bitcoin::Txid,
        include_watchonly: Option<bool>,
    ) -> Result<json::GetTransactionResult> {
        let support_verbose = self.version()? >= 19_00_00;

        self.handle_request(requests::get_transaction(txid, include_watchonly, support_verbose))
    }

    fn list_transactions(
        &self,
        label: Option<&str>,
        count: Option<usize>,
        skip: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<json::ListTransactionResult>> {
        self.handle_request(requests::list_transactions(
            label.as_ref(), count, skip, include_watchonly,
        ))
    }

    fn list_since_block(
        &self,
        block_hash: Option<&bitcoin::BlockHash>,
        target_confirmations: Option<usize>,
        include_watchonly: Option<bool>,
        include_removed: Option<bool>,
    ) -> Result<json::ListSinceBlockResult> {
        self.handle_request(requests::list_since_block(
            block_hash, target_confirmations, include_watchonly, include_removed,
        ))
    }

    fn get_tx_out(
        &self,
        txid: &bitcoin::Txid,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<json::GetTxOutResult>> {
        self.handle_request(requests::get_tx_out(txid, vout, include_mempool))
    }

    fn get_tx_out_proof(
        &self,
        txids: &[bitcoin::Txid],
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<Vec<u8>> {
        self.handle_request(requests::get_tx_out_proof(&txids, block_hash))
    }

    fn import_public_key(
        &self,
        public_key: &PublicKey,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        self.handle_request(requests::import_public_key(public_key, label.as_ref(), rescan))
    }

    fn import_private_key(
        &self,
        private_key: &PrivateKey,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        self.handle_request(requests::import_private_key(private_key, label.as_ref(), rescan))
    }

    fn import_address(
        &self,
        address: &(impl AddressParam + ?Sized),
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        self.handle_request(requests::import_address(
            &StringSerializeWrapper(address), label.as_ref(), rescan,
        ))
    }

    fn import_address_script(
        &self,
        script: &ScriptBuf,
        label: Option<&str>,
        rescan: Option<bool>,
        p2sh: Option<bool>,
    ) -> Result<()> {
        self.handle_request(requests::import_address_script(script, label.as_ref(), rescan, p2sh))
    }

    fn import_multi(
        &self,
        requests: &[json::ImportMultiRequest],
        options: Option<&json::ImportMultiOptions>,
    ) -> Result<Vec<json::ImportMultiResult>> {
        self.handle_request(requests::import_multi(&requests, options))
    }

    fn import_descriptors(
        &self,
        requests: &[json::ImportDescriptors],
    ) -> Result<Vec<json::ImportMultiResult>> {
        self.handle_request(requests::import_descriptors(&requests))
    }

    fn set_label(
        &self,
        address: &(impl AddressParam + ?Sized),
        label: &str,
    ) -> Result<()> {
        self.handle_request(requests::set_label(&StringSerializeWrapper(address), &label))
    }

    fn key_pool_refill(&self, new_size: Option<usize>) -> Result<()> {
        self.handle_request(requests::key_pool_refill(new_size))
    }

    fn list_unspent(
        &self,
        minconf: Option<usize>,
        maxconf: Option<usize>,
        addresses: Option<&[impl AddressParam]>,
        include_unsafe: Option<bool>,
        query_options: Option<&json::ListUnspentQueryOptions>,
    ) -> Result<Vec<json::ListUnspentResultEntry>> {
        self.handle_request(requests::list_unspent(
            minconf, maxconf, addresses.map(|a| StringListSerializeWrapper(a)).as_ref(),
            include_unsafe, query_options,
        ))
    }

    /// To unlock, use [unlock_unspent].
    fn lock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        self.handle_request(requests::lock_unspent(&OutPointListObjectSerializeWrapper(outputs)))
    }

    fn unlock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        self.handle_request(requests::unlock_unspent(&OutPointListObjectSerializeWrapper(outputs)))
    }

    fn unlock_unspent_all(&self) -> Result<bool> {
        self.handle_request(requests::unlock_unspent_all())
    }

    fn list_received_by_address(
        &self,
        address_filter: Option<&(impl AddressParam + ?Sized)>,
        minconf: Option<u32>,
        include_empty: Option<bool>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<json::ListReceivedByAddressResult>> {
        self.handle_request(requests::list_received_by_address(
            address_filter.map(|a| StringSerializeWrapper(a)).as_ref(), minconf, include_empty,
            include_watchonly,
        ))
    }

    fn create_raw_transaction_hex(
        &self,
        inputs: &[json::CreateRawTransactionInput],
        outputs: &[json::CreateRawTransactionOutput],
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<String> {
        self.handle_request(requests::create_raw_transaction_hex(
            &inputs, &outputs, locktime, replaceable,
        ))
    }

    fn create_raw_transaction(
        &self,
        inputs: &[json::CreateRawTransactionInput],
        outputs: &[json::CreateRawTransactionOutput],
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<Transaction> {
        self.handle_request(requests::create_raw_transaction(
            &inputs, &outputs, locktime, replaceable,
        ))
    }

    fn decode_raw_transaction(
        &self,
        tx: &(impl TxParam + ?Sized),
        is_witness: Option<bool>,
    ) -> Result<json::DecodeRawTransactionResult> {
        self.handle_request(requests::decode_raw_transaction(
            &HexSerializeWrapper(tx), is_witness,
        ))
    }

    fn fund_raw_transaction(
        &self,
        tx: &(impl TxParam + ?Sized),
        options: Option<&json::FundRawTransactionOptions>,
        is_witness: Option<bool>,
    ) -> Result<json::FundRawTransactionResult> {
        self.handle_request(requests::fund_raw_transaction(
            &HexSerializeWrapper(tx), options, is_witness,
        ))
    }

    fn sign_raw_transaction_with_wallet(
        &self,
        tx: &(impl TxParam + ?Sized),
        inputs: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<&impl SighashParam>,
    ) -> Result<json::SignRawTransactionResult> {
        let sighash = sighash_type.as_ref().map(|v| StringSerializeWrapper(*v));
        self.handle_request(requests::sign_raw_transaction_with_wallet(
            &HexSerializeWrapper(tx),
            inputs.as_ref(),
            sighash.as_ref(),
        ))
    }

    fn sign_raw_transaction_with_key(
        &self,
        tx: &(impl TxParam + ?Sized),
        private_keys: &[PrivateKey],
        inputs: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<&impl SighashParam>,
    ) -> Result<json::SignRawTransactionResult> {
        let sighash = sighash_type.as_ref().map(|v| StringSerializeWrapper(*v));
        self.handle_request(requests::sign_raw_transaction_with_key(
            &HexSerializeWrapper(tx), &private_keys, inputs.as_ref(), sighash.as_ref(),
        ))
    }

    /// Fee rate per kvb.
    fn test_mempool_accept<'r>(
        &self,
        raw_txs: &[impl TxParam],
        max_fee_rate: Option<FeeRate>,
    ) -> Result<Vec<json::TestMempoolAcceptResult>> {
        let fr_btc_per_kvb = max_fee_rate.map(|fr| {
            let per_kvb = fr.to_per_kvb()
                .ok_or_else(|| Error::InvalidArguments("fee rate overflow".into()))?;
            Result::<_>::Ok(per_kvb.to_btc())
        }).transpose()?;

        self.handle_request(requests::test_mempool_accept(
            &HexListSerializeWrapper(raw_txs), fr_btc_per_kvb,
        ))
    }

    fn stop(&self) -> Result<String> {
        self.handle_request(requests::stop())
    }

    fn verify_message(
        &self,
        address: &(impl AddressParam + ?Sized),
        signature: &Signature,
        message: &str,
    ) -> Result<bool> {
        self.handle_request(requests::verify_message(
            &StringSerializeWrapper(address), signature, &message,
        ))
    }

    fn get_new_address(
        &self,
        label: Option<&str>,
        address_type: Option<json::AddressType>,
    ) -> Result<UncheckedAddress> {
        self.handle_request(requests::get_new_address(label.as_ref(), address_type.as_ref()))
    }

    fn get_raw_change_address(
        &self,
        address_type: Option<json::AddressType>,
    ) -> Result<UncheckedAddress> {
        self.handle_request(requests::get_raw_change_address(address_type.as_ref()))
    }

    fn get_address_info(
        &self,
        address: &(impl AddressParam + ?Sized),
    ) -> Result<json::GetAddressInfoResult> {
        self.handle_request(requests::get_address_info(&StringSerializeWrapper(address)))
    }

    fn generate_to_address(
        &self,
        block_num: u64,
        address: &(impl AddressParam + ?Sized),
        max_tries: Option<usize>,
    ) -> Result<Vec<bitcoin::BlockHash>> {
        self.handle_request(requests::generate_to_address(
            block_num, &StringSerializeWrapper(address), max_tries,
        ))
    }

    // NB This call is no longer available on recent Bitcoin Core versions.
    #[deprecated]
    fn generate(
        &self,
        block_num: u64,
        max_tries: Option<usize>,
    ) -> Result<Vec<bitcoin::BlockHash>> {
        self.handle_request(requests::generate(block_num, max_tries))
    }

    fn invalidate_block(&self, block_hash: &bitcoin::BlockHash) -> Result<()> {
        self.handle_request(requests::invalidate_block(block_hash))
    }

    fn reconsider_block(&self, block_hash: &bitcoin::BlockHash) -> Result<()> {
        self.handle_request(requests::reconsider_block(block_hash))
    }

    fn get_mempool_info(&self) -> Result<json::GetMempoolInfoResult> {
        self.handle_request(requests::get_mempool_info())
    }

    fn get_raw_mempool(&self) -> Result<Vec<bitcoin::Txid>> {
        self.handle_request(requests::get_raw_mempool())
    }

    fn get_mempool_entry(&self, txid: &bitcoin::Txid) -> Result<json::GetMempoolEntryResult> {
        self.handle_request(requests::get_mempool_entry(txid))
    }

    fn get_chain_tips(&self) -> Result<json::GetChainTipsResult> {
        self.handle_request(requests::get_chain_tips())
    }

    //TODO(stevenroose) make this call more ergonomic, it's getting insane
    // NB the [avoid_reuse] argument is not supported for Bitcoin Core version 0.18 and older.
    // NB the [fee_rate] argument is not supported for Bitcoin Core versions 0.19 and older.
    fn send_to_address(
        &self,
        address: &(impl AddressParam + ?Sized),
        amount: Amount,
        comment: Option<&str>,
        comment_to: Option<&str>,
        subtract_fee: Option<bool>,
        replaceable: Option<bool>,
        confirmation_target: Option<u32>,
        estimate_mode: Option<json::EstimateMode>,
        avoid_reuse: Option<bool>,
        fee_rate: Option<FeeRate>,
    ) -> Result<bitcoin::Txid> {
        let support_verbose = self.version()? >= 21_00_00;

        self.handle_request(requests::send_to_address(
            &StringSerializeWrapper(address), amount, comment.as_ref(), comment_to.as_ref(),
            subtract_fee, replaceable, confirmation_target, estimate_mode.as_ref(), avoid_reuse,
            support_verbose, fee_rate.map(|fr| fr.to_per_vb_ceil().to_sat()),
        ))
    }

    fn add_node(&self, addr: &str) -> Result<()> {
        self.handle_request(requests::add_node(&addr))
    }

    fn add_node_onetry(&self, addr: &str) -> Result<()> {
        self.handle_request(requests::add_node_onetry(&addr))
    }

    fn remove_node(&self, addr: &str) -> Result<()> {
        self.handle_request(requests::remove_node(&addr))
    }

    fn disconnect_node(&self, addr: &str) -> Result<()> {
        self.handle_request(requests::disconnect_node(&addr))
    }

    fn disconnect_node_by_id(&self, node_id: u32) -> Result<()> {
        self.handle_request(requests::disconnect_node_by_id(node_id))
    }

    fn get_added_node_info(
        &self,
        node: &str,
    ) -> Result<Vec<json::GetAddedNodeInfoResult>> {
        self.handle_request(requests::get_added_node_info(&node))
    }

    fn get_added_nodes_info(&self) -> Result<Vec<json::GetAddedNodeInfoResult>> {
        self.handle_request(requests::get_added_nodes_info())
    }

    fn get_node_addresses(
        &self,
        count: Option<usize>,
    ) -> Result<Vec<json::GetNodeAddressesResult>> {
        self.handle_request(requests::get_node_addresses(count))
    }

    fn list_banned(&self) -> Result<Vec<json::ListBannedResult>> {
        self.handle_request(requests::list_banned())
    }

    fn clear_banned(&self) -> Result<()> {
        self.handle_request(requests::clear_banned())
    }

    fn add_ban(&self, subnet: &str, bantime: u64, absolute: bool) -> Result<()> {
        self.handle_request(requests::add_ban(&subnet, bantime, absolute))
    }

    fn remove_ban(&self, subnet: &str) -> Result<()> {
        self.handle_request(requests::remove_ban(&subnet))
    }

    fn set_network_active(&self, state: bool) -> Result<bool> {
        self.handle_request(requests::set_network_active(state))
    }

    fn get_peer_info(&self) -> Result<Vec<json::GetPeerInfoResult>> {
        self.handle_request(requests::get_peer_info())
    }

    fn ping(&self) -> Result<()> {
        self.handle_request(requests::ping())
    }

    fn send_raw_transaction(
        &self,
        tx: &(impl TxParam + ?Sized),
    ) -> Result<bitcoin::Txid> {
        self.handle_request(requests::send_raw_transaction(&HexSerializeWrapper(tx)))
    }

    fn estimate_smart_fee(
        &self,
        conf_target: u16,
        estimate_mode: Option<json::EstimateMode>,
    ) -> Result<json::EstimateSmartFeeResult> {
        self.handle_request(requests::estimate_smart_fee(conf_target, estimate_mode.as_ref()))
    }

    fn wait_for_new_block(&self, timeout: Option<u64>) -> Result<json::BlockRef> {
        self.handle_request(requests::wait_for_new_block(timeout))
    }

    fn wait_for_block(
        &self,
        block_hash: &bitcoin::BlockHash,
        timeout: Option<u64>,
    ) -> Result<json::BlockRef> {
        self.handle_request(requests::wait_for_block(block_hash, timeout))
    }

    fn get_descriptor_info(
        &self,
        descriptor: &str,
    ) -> Result<json::GetDescriptorInfoResult> {
        self.handle_request(requests::get_descriptor_info(&descriptor))
    }

    fn derive_addresses(
        &self,
        descriptor: &str,
        range: Option<&[u32; 2]>,
    ) -> Result<Vec<UncheckedAddress>> {
        self.handle_request(requests::derive_addresses(&descriptor, range))
    }

    fn create_psbt_raw(
        &self,
        inputs: &[json::CreateRawTransactionInput],
        outputs: &[json::CreateRawTransactionOutput],
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<String> {
        self.handle_request(requests::create_psbt_raw(
            &inputs, &outputs, locktime, replaceable,
        ))
    }

    fn create_psbt(
        &self,
        inputs: &[json::CreateRawTransactionInput],
        outputs: &[json::CreateRawTransactionOutput],
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<PartiallySignedTransaction> {
        self.handle_request(requests::create_psbt(
            &inputs, &outputs, locktime, replaceable,
        ))
    }

    fn wallet_create_funded_psbt(
        &self,
        inputs: &[json::CreateRawTransactionInput],
        outputs: &[json::CreateRawTransactionOutput],
        locktime: Option<i64>,
        options: Option<&json::WalletCreateFundedPsbtOptions>,
        include_bip32_derivations: Option<bool>,
    ) -> Result<json::WalletCreateFundedPsbtResult> {
        self.handle_request(requests::wallet_create_funded_psbt(
            &inputs, &outputs, locktime, options, include_bip32_derivations,
        ))
    }

    /// NB the [sighash_type] argument is not optional in all version of Bitcoin Core.
    fn wallet_process_psbt(
        &self,
        psbt: &(impl PsbtParam + ?Sized),
        sign: Option<bool>,
        sighash_type: Option<&json::SigHashType>,
        include_bip32_derivations: Option<bool>,
    ) -> Result<json::WalletProcessPsbtResult> {
        // Somehow if the bip32derivs parameter is set, the sighashtype is not optional.
        let version = self.version()?;
        if version >= 18_00_00 && version <= 22_00_00
            && include_bip32_derivations.is_some() && sighash_type.is_none()
        {
            return Err(Error::InvalidArguments(format!(
                "the `sighash_type` argument is required when the `include_bip32_derivations` \
                argument is provided"
            )));
        }

        self.handle_request(requests::wallet_process_psbt(
            &StringSerializeWrapper(psbt), sign, sighash_type, include_bip32_derivations,
        ))
    }

    fn join_psbts_raw(&self, psbts: &[impl PsbtParam]) -> Result<String> {
        self.handle_request(requests::join_psbts_raw(&StringListSerializeWrapper(psbts)))
    }

    fn join_psbts(&self, psbts: &[impl PsbtParam]) -> Result<PartiallySignedTransaction> {
        self.handle_request(requests::join_psbts(&StringListSerializeWrapper(psbts)))
    }

    fn combine_psbt_raw(&self, psbts: &[impl PsbtParam]) -> Result<String> {
        self.handle_request(requests::combine_psbt_raw(&StringListSerializeWrapper(psbts)))
    }

    fn combine_psbt(&self, psbts: &[impl PsbtParam]) -> Result<PartiallySignedTransaction> {
        self.handle_request(requests::combine_psbt(&StringListSerializeWrapper(psbts)))
    }

    fn combine_raw_transaction_hex(&self, txs: &[impl TxParam]) -> Result<String> {
        self.handle_request(requests::combine_raw_transaction_hex(&HexListSerializeWrapper(txs)))
    }

    fn combine_raw_transaction(&self, txs: &[impl TxParam]) -> Result<Transaction> {
        self.handle_request(requests::combine_raw_transaction(&HexListSerializeWrapper(txs)))
    }

    fn finalize_psbt(
        &self,
        psbt: &(impl PsbtParam + ?Sized),
        extract: Option<bool>,
    ) -> Result<json::FinalizePsbtResult> {
        self.handle_request(requests::finalize_psbt(&StringSerializeWrapper(psbt), extract))
    }

    fn rescan_blockchain(
        &self,
        start_height: Option<usize>,
        stop_height: Option<usize>,
    ) -> Result<(usize, Option<usize>)> {
        self.handle_request(requests::rescan_blockchain(start_height, stop_height))
    }

    fn get_tx_out_set_info(
        &self,
        hash_type: Option<json::TxOutSetHashType>,
        target_block_ref: Option<impl BlockRef>,
        use_index: Option<bool>,
    ) -> Result<json::GetTxOutSetInfoResult> {
        self.handle_request(requests::get_tx_out_set_info(
            hash_type.as_ref(), target_block_ref.as_ref(), use_index,
        ))
    }

    fn get_net_totals(&self) -> Result<json::GetNetTotalsResult> {
        self.handle_request(requests::get_net_totals())
    }

    fn get_network_hash_ps(
        &self,
        nb_blocks: Option<u64>,
        height: Option<u64>,
    ) -> Result<f64> {
        self.handle_request(requests::get_network_hash_ps(nb_blocks, height))
    }

    fn uptime(&self) -> Result<u64> {
        self.handle_request(requests::uptime())
    }

    fn submit_block(&self, block: &(impl BlockParam + ?Sized)) -> Result<()> {
        self.handle_request(requests::submit_block(&HexSerializeWrapper(block)))
    }

    fn scan_tx_out_set_blocking(
        &self,
        descriptors: &[json::ScanTxOutRequest],
    ) -> Result<json::ScanTxOutResult> {
        self.handle_request(requests::scan_tx_out_set_blocking(&descriptors))
    }
}

impl<T: jsonrpc::SyncTransport> SyncClient for Client<T> {
    fn version(&self) -> Result<usize> {
        let ver = self.version.load(atomic::Ordering::Relaxed);

        if ver > 0 {
            Ok(ver)
        } else {
            self.refresh_version()?;
            Ok(self.version.load(atomic::Ordering::Relaxed))
        }
    }

    fn refresh_version(&self) -> Result<()> {
        let ver = self.get_version()?;
        self.version.store(ver, atomic::Ordering::Relaxed);
        Ok(())
    }

    #[inline(always)]
    fn handle_request<'r, R>(&self, req: Request<'r, R>) -> Result<R> {
        Ok(req.get_sync(&self.client)?)
    }
}
