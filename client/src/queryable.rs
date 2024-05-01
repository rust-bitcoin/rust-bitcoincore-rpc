// SPDX-License-Identifier: CC0-1.0

use crate::bitcoin;
use crate::client::{Result, RpcApi};

/// A type that can be queried from Bitcoin Core.
pub trait Queryable<C: RpcApi>: Sized {
    /// Type of the ID used to query the item.
    type Id;
    /// Query the item using `rpc` and convert to `Self`.
    fn query(rpc: &C, id: &Self::Id) -> Result<Self>;
}

impl<C: RpcApi> Queryable<C> for bitcoin::block::Block {
    type Id = bitcoin::BlockHash;

    fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getblock";
        let hex: String = rpc.call(rpc_name, &[serde_json::to_value(id)?, 0.into()])?;
        Ok(bitcoin::consensus::encode::deserialize_hex(&hex)?)
    }
}

impl<C: RpcApi> Queryable<C> for bitcoin::transaction::Transaction {
    type Id = bitcoin::Txid;

    fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getrawtransaction";
        let hex: String = rpc.call(rpc_name, &[serde_json::to_value(id)?])?;
        Ok(bitcoin::consensus::encode::deserialize_hex(&hex)?)
    }
}

impl<C: RpcApi> Queryable<C> for Option<crate::json::GetTxOutResult> {
    type Id = bitcoin::OutPoint;

    fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        rpc.get_tx_out(&id.txid, id.vout, Some(true))
    }
}
