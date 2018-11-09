use bitcoin::util::hash::Sha256dHash;
use client::Client;
use client::Result;

/// A type that can be used as an id when querying for `Queryable`
// TODO: Unnecessary? Always `Sha256dHash`? --dpc
pub trait Id {
    fn to_json_value(&self) -> serde_json::value::Value;
}

impl Id for Sha256dHash {
    fn to_json_value(&self) -> serde_json::value::Value {
        self.to_string().into()
    }
}

/// A type that can be queried from the Node
pub trait Queryable: Sized {
    /// Type of the id used to query the item
    type Id: Id;
    /// Query the item using `rpc` and convert to `Self`
    fn query(rpc: &mut Client, id: &Self::Id) -> Result<Self>;
}

impl Queryable for bitcoin::blockdata::block::Block {
    type Id = Sha256dHash;

    fn query(rpc: &mut Client, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getblock";
        let hex: String = rpc.call(rpc_name, &[id.to_json_value(), 0.into()])?;
        let bytes = bitcoin::util::misc::hex_bytes(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }
}

impl Queryable for bitcoin::blockdata::transaction::Transaction {
    type Id = Sha256dHash;

    fn query(rpc: &mut Client, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getrawtransaction";
        let hex: String = rpc.call(rpc_name, &[id.to_json_value()])?;
        let bytes = bitcoin::util::misc::hex_bytes(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }
}
