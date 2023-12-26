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
pub use bitcoinsv_rpc_json as json;

mod client;
mod error;

pub use crate::client::*;
pub use crate::error::Error;

