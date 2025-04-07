#![crate_name = "bitcoinsv_rpc"]
#![crate_type = "rlib"]

/// # Rust Client for Bitcoin SV API
///
/// This is a client library for the Bitcoin SV JSON-RPC API.
///
/// Example usage:
/// ```norun
///    let rpc_client = Client::new("http://127.0.0.1:8332", Auth::UserPass("username".to_string(), "password".to_string())).unwrap();
///    let best_block_hash = rpc_client.get_best_block_hash().unwrap();
///    println!("best block hash: {}", best_block_hash);
/// ```
///
/// For documentation on which methods are available, see the [RpcApi] trait.

#[macro_use]
extern crate log;
#[macro_use] // `macro_use` is needed for v1.24.0 compilation.
extern crate serde;

pub extern crate jsonrpc;

pub extern crate bitcoinsv_rpc_json;
pub use bitcoinsv_rpc_json as json;
pub use json::*;

mod client;
mod error;

pub use crate::client::{Auth, Client, RpcApi};
pub use crate::error::Error;
