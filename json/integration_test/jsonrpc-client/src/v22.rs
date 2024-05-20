//! Test the Bitcoin Core v22 JSON-RPC API.

use anyhow;
use bitcoincore_rpc_json::*;

/// An RPC client.
#[jsonrpc_client::implement(BitcoindRpc)]
pub struct Client {
    inner: reqwest::Client,
    base_url: jsonrpc_client::Url,
}

impl Client {
    /// Creates a new [`Client`].
    pub fn new(base_url: String) -> anyhow::Result<Self> {
        Ok(Self {
            inner: reqwest::Client::new(),
            base_url: base_url.parse()?,
        })
    }
}

/// Implement JSON-RPC call: `getblockchaininfo`.
#[jsonrpc_client::api(version = "1.0")]
pub trait BitcoindRpc {
    /// Implement JSON-RPC call: `getblockchaininfo`.
    async fn getblockchaininfo(&self) -> GetBlockchainInfoResult;

    /// Implement JSON-RPC call: `getnetworkinfo`.
    async fn getnetworkinfo(&self) -> GetNetworkInfoResult;

    /// Implement JSON-RPC call: `getindexinfo`.
    async fn getindexinfo(&self) -> GetIndexInfoResult;
}
