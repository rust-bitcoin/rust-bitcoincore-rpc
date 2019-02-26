// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use bitcoin;
use serde_json;

use bitcoin_hashes::sha256d;
use client::RpcApi;
use client::Result;

/// A type that can be queried from Bitcoin Core.
pub trait Queryable<C: RpcApi>: Sized {
    /// Type of the ID used to query the item.
    type Id;
    /// Query the item using `rpc` and convert to `Self`.
    fn query(rpc: &C, id: &Self::Id) -> Result<Self>;
}

impl<C: RpcApi> Queryable<C> for bitcoin::blockdata::block::Block {
    type Id = sha256d::Hash;

    fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getblock";
        let hex: String = rpc.call(rpc_name, &[serde_json::to_value(id)?, 0.into()])?;
        let bytes = bitcoin::util::misc::hex_bytes(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }
}

impl<C: RpcApi> Queryable<C> for bitcoin::blockdata::transaction::Transaction {
    type Id = sha256d::Hash;

    fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getrawtransaction";
        let hex: String = rpc.call(rpc_name, &[serde_json::to_value(id)?])?;
        let bytes = bitcoin::util::misc::hex_bytes(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }
}

impl<C: RpcApi> Queryable<C> for Option<::json::GetTxOutResult> {
    type Id = bitcoin::OutPoint;

    fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        rpc.get_tx_out(&id.txid, id.vout, Some(true))
    }
}
