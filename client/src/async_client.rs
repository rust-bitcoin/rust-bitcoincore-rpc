
use std::sync::atomic;

use async_trait::async_trait;
use crate::bitcoin::secp256k1::ecdsa::Signature;
use crate::bitcoin::{
    self, Address, Amount, Block, OutPoint, PrivateKey, PublicKey,
    ScriptBuf, Transaction, FeeRate,
};
use crate::bitcoin::psbt::PartiallySignedTransaction;
use crate::bitcoin::block::Header as BlockHeader;
type UncheckedAddress = Address<crate::bitcoin::address::NetworkUnchecked>;

use jsonrpc::client::{Param, List, Request, Params};

use crate::{
    json, requests, Client, AddressParam, Error, Result, BlockParam, BlockRef, PsbtParam,
    SighashParam, TxParam,
};
use crate::serialize::{
    HexSerializeWrapper, HexListSerializeWrapper,
    OutPointListObjectSerializeWrapper,
    StringListSerializeWrapper, StringSerializeWrapper,
};

#[async_trait(?Send)]
pub trait AsyncClient {
    /// The internal method to make a request.
    async fn handle_request<'r, T>(&self, req: Request<'r, T>) -> Result<T>;

    /// Make a manual call.
    async fn call<T: for<'a> serde::de::Deserialize<'a> + 'static>(
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
        ).await
    }

    /// Get cached version of the version.
    async fn version(&self) -> Result<usize>;

    /// Refresh the cached version by asking the server again.
    async fn refresh_version(&self) -> Result<()>;

    async fn get_version(&self) -> Result<usize> {
        self.handle_request(requests::version()).await
    }

    async fn get_network_info(&self) -> Result<json::GetNetworkInfoResult> {
        self.handle_request(requests::get_network_info()).await
    }

    async fn get_index_info(&self) -> Result<json::GetIndexInfoResult> {
        self.handle_request(requests::get_index_info()).await
    }

    async fn add_multisig_address(
        &self,
        nrequired: usize,
        keys: &[json::PubKeyOrAddress],
        label: Option<&str>,
        address_type: Option<json::AddressType>,
    ) -> Result<json::AddMultiSigAddressResult> {
        self.handle_request(requests::add_multisig_address(
            nrequired, &keys, label.as_ref(), address_type.as_ref(),
        )).await
    }

    async fn load_wallet(&self, wallet: &str) -> Result<json::LoadWalletResult> {
        self.handle_request(requests::load_wallet(&wallet)).await
    }

    async fn unload_wallet(&self, wallet: Option<&str>) -> Result<json::UnloadWalletResult> {
        self.handle_request(requests::unload_wallet(wallet.as_ref())).await
    }

    async fn create_wallet(
        &self,
        wallet: &str,
        disable_private_keys: Option<bool>,
        blank: Option<bool>,
        passphrase: Option<&str>,
        avoid_reuse: Option<bool>,
    ) -> Result<json::LoadWalletResult> {
        self.handle_request(requests::create_wallet(
            &wallet, disable_private_keys, blank, passphrase.as_ref(), avoid_reuse,
        )).await
    }

    async fn list_wallets(&self) -> Result<Vec<String>> {
        self.handle_request(requests::list_wallets()).await
    }

    async fn list_wallet_dir(&self) -> Result<Vec<String>> {
        self.handle_request(requests::list_wallet_dir()).await
    }

    async fn get_wallet_info(&self) -> Result<json::GetWalletInfoResult> {
        self.handle_request(requests::get_wallet_info()).await
    }

    async fn backup_wallet(&self, destination: &str) -> Result<()> {
        self.handle_request(requests::backup_wallet(&destination)).await
    }

    async fn dump_private_key(
        &self,
        address: &(impl AddressParam + ?Sized),
    ) -> Result<PrivateKey> {
        self.handle_request(requests::dump_private_key(&StringSerializeWrapper(address))).await
    }

    async fn encrypt_wallet(&self, passphrase: &str) -> Result<String> {
        self.handle_request(requests::encrypt_wallet(&passphrase)).await
    }

    async fn get_difficulty(&self) -> Result<f64> {
        self.handle_request(requests::get_difficulty()).await
    }

    async fn get_connection_count(&self) -> Result<usize> {
        self.handle_request(requests::get_connection_count()).await
    }

    async fn get_block(&self, hash: &bitcoin::BlockHash) -> Result<Block> {
        self.handle_request(requests::get_block(hash)).await
    }

    async fn get_block_hex(&self, hash: &bitcoin::BlockHash) -> Result<String> {
        self.handle_request(requests::get_block_hex(hash)).await
    }

    async fn get_block_info(&self, hash: &bitcoin::BlockHash) -> Result<json::GetBlockResult> {
        self.handle_request(requests::get_block_info(hash)).await
    }
    //TODO(stevenroose) add getblock_txs

    async fn get_block_header(&self, hash: &bitcoin::BlockHash) -> Result<BlockHeader> {
        self.handle_request(requests::get_block_header(hash)).await
    }

    async fn get_block_header_info(
        &self,
        hash: &bitcoin::BlockHash,
    ) -> Result<json::GetBlockHeaderResult> {
        self.handle_request(requests::get_block_header_info(hash)).await
    }

    async fn get_mining_info(&self) -> Result<json::GetMiningInfoResult> {
        self.handle_request(requests::get_mining_info()).await
    }

    async fn get_block_template(
        &self,
        mode: json::GetBlockTemplateModes,
        rules: &[json::GetBlockTemplateRules],
        capabilities: &[json::GetBlockTemplateCapabilities],
    ) -> Result<json::GetBlockTemplateResult> {
        self.handle_request(requests::get_block_template(&mode, &rules, &capabilities)).await
    }

    async fn get_blockchain_info(&self) -> Result<json::GetBlockchainInfoResult> {
        self.handle_request(requests::get_blockchain_info()).await
    }

    async fn get_block_count(&self) -> Result<u64> {
        self.handle_request(requests::get_block_count()).await
    }

    async fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash> {
        self.handle_request(requests::get_best_block_hash()).await
    }

    async fn get_block_hash(&self, height: u64) -> Result<bitcoin::BlockHash> {
        self.handle_request(requests::get_block_hash(height)).await
    }
    
    async fn get_block_stats(
        &self,
        block_ref: impl BlockRef + 'async_trait,
    ) -> Result<json::GetBlockStatsResult> {
        self.handle_request(requests::get_block_stats(&block_ref)).await
    }

    async fn get_block_stats_fields(
        &self,
        block_ref: impl BlockRef + 'async_trait,
        fields: &[json::BlockStatsFields],
    ) -> Result<json::GetBlockStatsResultPartial> {
        self.handle_request(requests::get_block_stats_fields(&block_ref, &fields)).await
    }

    async fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<Transaction> {
        self.handle_request(requests::get_raw_transaction(txid, block_hash)).await
    }

    async fn get_raw_transaction_hex(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<String> {
        self.handle_request(requests::get_raw_transaction_hex(txid, block_hash)).await
    }

    async fn get_raw_transaction_info(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<json::GetRawTransactionResult> {
        self.handle_request(requests::get_raw_transaction_info(txid, block_hash)).await
    }

    async fn get_block_filter(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<json::GetBlockFilterResult> {
        self.handle_request(requests::get_block_filter(block_hash)).await
    }

    async fn get_balance(
        &self,
        minconf: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Amount> {
        self.handle_request(requests::get_balance(minconf, include_watchonly)).await
    }

    async fn get_balances(&self) -> Result<json::GetBalancesResult> {
        self.handle_request(requests::get_balances()).await
    }

    async fn get_received_by_address(
        &self,
        address: &(impl AddressParam + ?Sized),
        minconf: Option<u32>,
    ) -> Result<Amount> {
        self.handle_request(requests::get_received_by_address(
            &StringSerializeWrapper(address), minconf,
        )).await
    }

    async fn get_transaction(
        &self,
        txid: &bitcoin::Txid,
        include_watchonly: Option<bool>,
    ) -> Result<json::GetTransactionResult> {
        let support_verbose = self.version().await? >= 19_00_00;

        self.handle_request(requests::get_transaction(txid, include_watchonly, support_verbose)).await
    }

    async fn list_transactions(
        &self,
        label: Option<&str>,
        count: Option<usize>,
        skip: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<json::ListTransactionResult>> {
        self.handle_request(requests::list_transactions(
            label.as_ref(), count, skip, include_watchonly,
        )).await
    }

    async fn list_since_block(
        &self,
        block_hash: Option<&bitcoin::BlockHash>,
        target_confirmations: Option<usize>,
        include_watchonly: Option<bool>,
        include_removed: Option<bool>,
    ) -> Result<json::ListSinceBlockResult> {
        self.handle_request(requests::list_since_block(
            block_hash, target_confirmations, include_watchonly, include_removed,
        )).await
    }

    async fn get_tx_out(
        &self,
        txid: &bitcoin::Txid,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<json::GetTxOutResult>> {
        self.handle_request(requests::get_tx_out(txid, vout, include_mempool)).await
    }

    async fn get_tx_out_proof(
        &self,
        txids: &[bitcoin::Txid],
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<Vec<u8>> {
        self.handle_request(requests::get_tx_out_proof(&txids, block_hash)).await
    }

    async fn import_public_key(
        &self,
        public_key: &PublicKey,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        self.handle_request(requests::import_public_key(public_key, label.as_ref(), rescan)).await
    }

    async fn import_private_key(
        &self,
        private_key: &PrivateKey,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        self.handle_request(requests::import_private_key(private_key, label.as_ref(), rescan)).await
    }

    async fn import_address(
        &self,
        address: &(impl AddressParam + ?Sized),
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        self.handle_request(requests::import_address(
            &StringSerializeWrapper(address), label.as_ref(), rescan,
        )).await
    }

    async fn import_address_script(
        &self,
        script: &ScriptBuf,
        label: Option<&str>,
        rescan: Option<bool>,
        p2sh: Option<bool>,
    ) -> Result<()> {
        self.handle_request(requests::import_address_script(script, label.as_ref(), rescan, p2sh)).await
    }

    async fn import_multi(
        &self,
        requests: &[json::ImportMultiRequest],
        options: Option<&json::ImportMultiOptions>,
    ) -> Result<Vec<json::ImportMultiResult>> {
        self.handle_request(requests::import_multi(&requests, options)).await
    }

    async fn import_descriptors(
        &self,
        requests: &[json::ImportDescriptors],
    ) -> Result<Vec<json::ImportMultiResult>> {
        self.handle_request(requests::import_descriptors(&requests)).await
    }

    async fn set_label(
        &self,
        address: &(impl AddressParam + ?Sized),
        label: &str,
    ) -> Result<()> {
        self.handle_request(requests::set_label(&StringSerializeWrapper(address), &label)).await
    }

    async fn key_pool_refill(&self, new_size: Option<usize>) -> Result<()> {
        self.handle_request(requests::key_pool_refill(new_size)).await
    }

    async fn list_unspent(
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
        )).await
    }

    /// To unlock, use [unlock_unspent].
    async fn lock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        self.handle_request(requests::lock_unspent(
            &OutPointListObjectSerializeWrapper(outputs),
        )).await
    }

    async fn unlock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        self.handle_request(requests::unlock_unspent(
            &OutPointListObjectSerializeWrapper(outputs),
        )).await
    }

    async fn unlock_unspent_all(&self) -> Result<bool> {
        self.handle_request(requests::unlock_unspent_all()).await
    }

    async fn list_received_by_address(
        &self,
        address_filter: Option<&(impl AddressParam + ?Sized)>,
        minconf: Option<u32>,
        include_empty: Option<bool>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<json::ListReceivedByAddressResult>> {
        self.handle_request(requests::list_received_by_address(
            address_filter.map(|a| StringSerializeWrapper(a)).as_ref(), minconf, include_empty,
            include_watchonly,
        )).await
    }

    async fn create_raw_transaction_hex(
        &self,
        inputs: &[json::CreateRawTransactionInput],
        outputs: &[json::CreateRawTransactionOutput],
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<String> {
        self.handle_request(requests::create_raw_transaction_hex(
            &inputs, &outputs, locktime, replaceable,
        )).await
    }

    async fn create_raw_transaction(
        &self,
        inputs: &[json::CreateRawTransactionInput],
        outputs: &[json::CreateRawTransactionOutput],
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<Transaction> {
        self.handle_request(requests::create_raw_transaction(
            &inputs, &outputs, locktime, replaceable,
        )).await
    }

    async fn decode_raw_transaction(
        &self,
        tx: &(impl TxParam + ?Sized),
        is_witness: Option<bool>,
    ) -> Result<json::DecodeRawTransactionResult> {
        self.handle_request(requests::decode_raw_transaction(
            &HexSerializeWrapper(tx), is_witness,
        )).await
    }

    async fn fund_raw_transaction(
        &self,
        tx: &(impl TxParam + ?Sized),
        options: Option<&json::FundRawTransactionOptions>,
        is_witness: Option<bool>,
    ) -> Result<json::FundRawTransactionResult> {
        self.handle_request(requests::fund_raw_transaction(
            &HexSerializeWrapper(tx), options, is_witness,
        )).await
    }

    async fn sign_raw_transaction_with_wallet(
        &self,
        tx: &(impl TxParam + ?Sized),
        inputs: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<&(impl SighashParam + 'async_trait)>,
    ) -> Result<json::SignRawTransactionResult> {
        let sighash = sighash_type.as_ref().map(|v| StringSerializeWrapper(*v));
        self.handle_request(requests::sign_raw_transaction_with_wallet(
            &HexSerializeWrapper(tx),
            inputs.as_ref(),
            sighash.as_ref(),
        )).await
    }

    async fn sign_raw_transaction_with_key(
        &self,
        tx: &(impl TxParam + ?Sized),
        private_keys: &[PrivateKey],
        inputs: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<&(impl SighashParam + 'async_trait)>,
    ) -> Result<json::SignRawTransactionResult> {
        let sighash = sighash_type.as_ref().map(|v| StringSerializeWrapper(*v));
        self.handle_request(requests::sign_raw_transaction_with_key(
            &HexSerializeWrapper(tx), &private_keys, inputs.as_ref(), sighash.as_ref(),
        )).await
    }

    /// Fee rate per kvb.
    async fn test_mempool_accept<'r>(
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
        )).await
    }

    async fn stop(&self) -> Result<String> {
        self.handle_request(requests::stop()).await
    }

    async fn verify_message(
        &self,
        address: &(impl AddressParam + ?Sized),
        signature: &Signature,
        message: &str,
    ) -> Result<bool> {
        self.handle_request(requests::verify_message(
            &StringSerializeWrapper(address), signature, &message,
        )).await
    }

    async fn get_new_address(
        &self,
        label: Option<&str>,
        address_type: Option<json::AddressType>,
    ) -> Result<UncheckedAddress> {
        self.handle_request(requests::get_new_address(label.as_ref(), address_type.as_ref())).await
    }

    async fn get_raw_change_address(
        &self,
        address_type: Option<json::AddressType>,
    ) -> Result<UncheckedAddress> {
        self.handle_request(requests::get_raw_change_address(address_type.as_ref())).await
    }

    async fn get_address_info(
        &self,
        address: &(impl AddressParam + ?Sized),
    ) -> Result<json::GetAddressInfoResult> {
        self.handle_request(requests::get_address_info(&StringSerializeWrapper(address))).await
    }

    async fn generate_to_address(
        &self,
        block_num: u64,
        address: &(impl AddressParam + ?Sized),
        max_tries: Option<usize>,
    ) -> Result<Vec<bitcoin::BlockHash>> {
        self.handle_request(requests::generate_to_address(
            block_num, &StringSerializeWrapper(address), max_tries,
        )).await
    }

    // NB This call is no longer available on recent Bitcoin Core versions.
    #[deprecated]
    async fn generate(
        &self,
        block_num: u64,
        max_tries: Option<usize>,
    ) -> Result<Vec<bitcoin::BlockHash>> {
        self.handle_request(requests::generate(block_num, max_tries)).await
    }

    async fn invalidate_block(&self, block_hash: &bitcoin::BlockHash) -> Result<()> {
        self.handle_request(requests::invalidate_block(block_hash)).await
    }

    async fn reconsider_block(&self, block_hash: &bitcoin::BlockHash) -> Result<()> {
        self.handle_request(requests::reconsider_block(block_hash)).await
    }

    async fn get_mempool_info(&self) -> Result<json::GetMempoolInfoResult> {
        self.handle_request(requests::get_mempool_info()).await
    }

    async fn get_raw_mempool(&self) -> Result<Vec<bitcoin::Txid>> {
        self.handle_request(requests::get_raw_mempool()).await
    }

    async fn get_mempool_entry(&self, txid: &bitcoin::Txid) -> Result<json::GetMempoolEntryResult> {
        self.handle_request(requests::get_mempool_entry(txid)).await
    }

    async fn get_chain_tips(&self) -> Result<json::GetChainTipsResult> {
        self.handle_request(requests::get_chain_tips()).await
    }

    //TODO(stevenroose) make this call more ergonomic, it's getting insane
    // NB the [avoid_reuse] argument is not supported for Bitcoin Core version 0.18 and older.
    // NB the [fee_rate] argument is not supported for Bitcoin Core versions 0.19 and older.
    async fn send_to_address(
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
        let support_verbose = self.version().await? >= 21_00_00;

        self.handle_request(requests::send_to_address(
            &StringSerializeWrapper(address), amount, comment.as_ref(), comment_to.as_ref(),
            subtract_fee, replaceable, confirmation_target, estimate_mode.as_ref(), avoid_reuse,
            support_verbose, fee_rate.map(|fr| fr.to_per_vb_ceil().to_sat()),
        )).await
    }

    async fn add_node(&self, addr: &str) -> Result<()> {
        self.handle_request(requests::add_node(&addr)).await
    }

    async fn add_node_onetry(&self, addr: &str) -> Result<()> {
        self.handle_request(requests::add_node_onetry(&addr)).await
    }

    async fn remove_node(&self, addr: &str) -> Result<()> {
        self.handle_request(requests::remove_node(&addr)).await
    }

    async fn disconnect_node(&self, addr: &str) -> Result<()> {
        self.handle_request(requests::disconnect_node(&addr)).await
    }

    async fn disconnect_node_by_id(&self, node_id: u32) -> Result<()> {
        self.handle_request(requests::disconnect_node_by_id(node_id)).await
    }

    async fn get_added_node_info(
        &self,
        node: &str,
    ) -> Result<Vec<json::GetAddedNodeInfoResult>> {
        self.handle_request(requests::get_added_node_info(&node)).await
    }

    async fn get_added_nodes_info(&self) -> Result<Vec<json::GetAddedNodeInfoResult>> {
        self.handle_request(requests::get_added_nodes_info()).await
    }

    async fn get_node_addresses(
        &self,
        count: Option<usize>,
    ) -> Result<Vec<json::GetNodeAddressesResult>> {
        self.handle_request(requests::get_node_addresses(count)).await
    }

    async fn list_banned(&self) -> Result<Vec<json::ListBannedResult>> {
        self.handle_request(requests::list_banned()).await
    }

    async fn clear_banned(&self) -> Result<()> {
        self.handle_request(requests::clear_banned()).await
    }

    async fn add_ban(&self, subnet: &str, bantime: u64, absolute: bool) -> Result<()> {
        self.handle_request(requests::add_ban(&subnet, bantime, absolute)).await
    }

    async fn remove_ban(&self, subnet: &str) -> Result<()> {
        self.handle_request(requests::remove_ban(&subnet)).await
    }

    async fn set_network_active(&self, state: bool) -> Result<bool> {
        self.handle_request(requests::set_network_active(state)).await
    }

    async fn get_peer_info(&self) -> Result<Vec<json::GetPeerInfoResult>> {
        self.handle_request(requests::get_peer_info()).await
    }

    async fn ping(&self) -> Result<()> {
        self.handle_request(requests::ping()).await
    }

    async fn send_raw_transaction(
        &self,
        tx: &(impl TxParam + ?Sized),
    ) -> Result<bitcoin::Txid> {
        self.handle_request(requests::send_raw_transaction(&HexSerializeWrapper(tx))).await
    }

    async fn estimate_smart_fee(
        &self,
        conf_target: u16,
        estimate_mode: Option<json::EstimateMode>,
    ) -> Result<json::EstimateSmartFeeResult> {
        self.handle_request(requests::estimate_smart_fee(conf_target, estimate_mode.as_ref())).await
    }

    async fn wait_for_new_block(&self, timeout: Option<u64>) -> Result<json::BlockRef> {
        self.handle_request(requests::wait_for_new_block(timeout)).await
    }

    async fn wait_for_block(
        &self,
        block_hash: &bitcoin::BlockHash,
        timeout: Option<u64>,
    ) -> Result<json::BlockRef> {
        self.handle_request(requests::wait_for_block(block_hash, timeout)).await
    }

    async fn get_descriptor_info(
        &self,
        descriptor: &str,
    ) -> Result<json::GetDescriptorInfoResult> {
        self.handle_request(requests::get_descriptor_info(&descriptor)).await
    }

    async fn derive_addresses(
        &self,
        descriptor: &str,
        range: Option<&[u32; 2]>,
    ) -> Result<Vec<UncheckedAddress>> {
        self.handle_request(requests::derive_addresses(&descriptor, range)).await
    }

    async fn create_psbt_raw(
        &self,
        inputs: &[json::CreateRawTransactionInput],
        outputs: &[json::CreateRawTransactionOutput],
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<String> {
        self.handle_request(requests::create_psbt_raw(
            &inputs, &outputs, locktime, replaceable,
        )).await
    }

    async fn create_psbt(
        &self,
        inputs: &[json::CreateRawTransactionInput],
        outputs: &[json::CreateRawTransactionOutput],
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<PartiallySignedTransaction> {
        self.handle_request(requests::create_psbt(
            &inputs, &outputs, locktime, replaceable,
        )).await
    }

    async fn wallet_create_funded_psbt(
        &self,
        inputs: &[json::CreateRawTransactionInput],
        outputs: &[json::CreateRawTransactionOutput],
        locktime: Option<i64>,
        options: Option<&json::WalletCreateFundedPsbtOptions>,
        include_bip32_derivations: Option<bool>,
    ) -> Result<json::WalletCreateFundedPsbtResult> {
        self.handle_request(requests::wallet_create_funded_psbt(
            &inputs, &outputs, locktime, options, include_bip32_derivations,
        )).await
    }

    /// NB the [sighash_type] argument is not optional in all version of Bitcoin Core.
    async fn wallet_process_psbt(
        &self,
        psbt: &(impl PsbtParam + ?Sized),
        sign: Option<bool>,
        sighash_type: Option<&json::SigHashType>,
        include_bip32_derivations: Option<bool>,
    ) -> Result<json::WalletProcessPsbtResult> {
        // Somehow if the bip32derivs parameter is set, the sighashtype is not optional.
        let version = self.version().await?;
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
        )).await
    }

    async fn join_psbts_raw(&self, psbts: &[impl PsbtParam]) -> Result<String> {
        self.handle_request(requests::join_psbts_raw(&StringListSerializeWrapper(psbts))).await
    }

    async fn join_psbts(&self, psbts: &[impl PsbtParam]) -> Result<PartiallySignedTransaction> {
        self.handle_request(requests::join_psbts(&StringListSerializeWrapper(psbts))).await
    }

    async fn combine_psbt_raw(&self, psbts: &[impl PsbtParam]) -> Result<String> {
        self.handle_request(requests::combine_psbt_raw(&StringListSerializeWrapper(psbts))).await
    }

    async fn combine_psbt(&self, psbts: &[impl PsbtParam]) -> Result<PartiallySignedTransaction> {
        self.handle_request(requests::combine_psbt(&StringListSerializeWrapper(psbts))).await
    }

    async fn combine_raw_transaction_hex(&self, txs: &[impl TxParam]) -> Result<String> {
        self.handle_request(
            requests::combine_raw_transaction_hex(&HexListSerializeWrapper(txs)),
        ).await
    }

    async fn combine_raw_transaction(&self, txs: &[impl TxParam]) -> Result<Transaction> {
        self.handle_request(
            requests::combine_raw_transaction(&HexListSerializeWrapper(txs)),
        ).await
    }

    async fn finalize_psbt(
        &self,
        psbt: &(impl PsbtParam + ?Sized),
        extract: Option<bool>,
    ) -> Result<json::FinalizePsbtResult> {
        self.handle_request(requests::finalize_psbt(&StringSerializeWrapper(psbt), extract)).await
    }

    async fn rescan_blockchain(
        &self,
        start_height: Option<usize>,
        stop_height: Option<usize>,
    ) -> Result<(usize, Option<usize>)> {
        self.handle_request(requests::rescan_blockchain(start_height, stop_height)).await
    }

    async fn get_tx_out_set_info(
        &self,
        hash_type: Option<json::TxOutSetHashType>,
        target_block_ref: Option<impl BlockRef + 'async_trait>,
        use_index: Option<bool>,
    ) -> Result<json::GetTxOutSetInfoResult> {
        self.handle_request(requests::get_tx_out_set_info(
            hash_type.as_ref(), target_block_ref.as_ref(), use_index,
        )).await
    }

    async fn get_net_totals(&self) -> Result<json::GetNetTotalsResult> {
        self.handle_request(requests::get_net_totals()).await
    }

    async fn get_network_hash_ps(
        &self,
        nb_blocks: Option<u64>,
        height: Option<u64>,
    ) -> Result<f64> {
        self.handle_request(requests::get_network_hash_ps(nb_blocks, height)).await
    }

    async fn uptime(&self) -> Result<u64> {
        self.handle_request(requests::uptime()).await
    }

    async fn submit_block(&self, block: &(impl BlockParam + ?Sized)) -> Result<()> {
        self.handle_request(requests::submit_block(&HexSerializeWrapper(block))).await
    }

    async fn scan_tx_out_set_blocking(
        &self,
        descriptors: &[json::ScanTxOutRequest],
    ) -> Result<json::ScanTxOutResult> {
        self.handle_request(requests::scan_tx_out_set_blocking(&descriptors)).await
    }

}

#[async_trait(?Send)]
impl<T: jsonrpc::AsyncTransport> AsyncClient for Client<T> {
    async fn version(&self) -> Result<usize> {
        let ver = self.version.load(atomic::Ordering::Relaxed);

        if ver > 0 {
            Ok(ver)
        } else {
            self.refresh_version().await?;
            Ok(self.version.load(atomic::Ordering::Relaxed))
        }
    }

    async fn refresh_version(&self) -> Result<()> {
        let ver = self.get_version().await?;
        self.version.store(ver, atomic::Ordering::Relaxed);
        Ok(())
    }

    #[inline(always)]
    async fn handle_request<'r, R>(&self, req: Request<'r, R>) -> Result<R> {
        Ok(req.get_async(&self.client).await?)
    }
}
