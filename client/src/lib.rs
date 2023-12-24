//! # Rust Client for Bitcoin SV API
//!
//! This is a client library for the Bitcoin SV JSON-RPC API.
//!

#![crate_name = "bitcoinsv_rpc"]
#![crate_type = "rlib"]

#[macro_use]
extern crate log;
#[allow(unused)]
#[macro_use] // `macro_use` is needed for v1.24.0 compilation.
extern crate serde;

pub extern crate jsonrpc;

pub extern crate bitcoinsv_rpc_json;
pub use crate::json::bitcoin;
pub use bitcoinsv_rpc_json as json;
use json::bitcoin::consensus::{Decodable, ReadExt};
use json::bitcoin::hex::HexToBytesIter;

mod client;
mod error;
mod queryable;

pub use crate::client::*;
pub use crate::error::Error;
pub use crate::queryable::*;

fn deserialize_hex<T: Decodable>(hex: &str) -> Result<T> {
    let mut reader = HexToBytesIter::new(&hex)?;
    let object = Decodable::consensus_decode(&mut reader)?;
    if reader.read_u8().is_ok() {
        Err(Error::BitcoinSerialization(bitcoin::consensus::encode::Error::ParseFailed(
            "data not consumed entirely when explicitly deserializing",
        )))
    } else {
        Ok(object)
    }
}
