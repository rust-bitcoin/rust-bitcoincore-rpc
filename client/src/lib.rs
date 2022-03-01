// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Rust Client for Bitcoin Core API
//!
//! This is a client library for the Bitcoin Core JSON-RPC API.
//!

#![crate_name = "bitcoincore_rpc"]
#![crate_type = "rlib"]

#[macro_use]
extern crate log;

pub extern crate jsonrpc;

pub extern crate bitcoincore_rpc_json;
pub use bitcoincore_rpc_json as json;

pub use crate::json::bitcoin;

mod client;
pub use client::*;

mod params;
pub use params::*;

mod sync_client;
pub use sync_client::SyncClient;

mod async_client;
pub use async_client::AsyncClient;

mod error;
pub use error::Error;

pub mod requests;
pub mod serialize;

/// Crate-specific Result type, shorthand for `std::result::Result` with our
/// crate-specific Error type;
pub type Result<T> = std::result::Result<T, Error>;
