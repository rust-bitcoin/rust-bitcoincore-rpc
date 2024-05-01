// SPDX-License-Identifier: CC0-1.0

//! # Rust Client for Bitcoin Core API
//!
//! This is a client library for the Bitcoin Core JSON-RPC API.
//!

#[macro_use]
extern crate log;
#[allow(unused)]
#[macro_use]
extern crate serde;

/// Re-export the `jsonrpc` crate.
pub extern crate jsonrpc;

/// Re-export the `bitcoin` crate.
pub use crate::json::bitcoin;
/// Re-export the `bitcoin-rpc-json` crate.
pub use bitcoincore_rpc_json as json;

mod client;
mod error;
mod queryable;

pub use crate::client::*;
pub use crate::error::Error;
pub use crate::queryable::*;
