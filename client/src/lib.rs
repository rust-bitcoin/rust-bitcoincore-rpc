// SPDX-License-Identifier: CC0-1.0

//! # Rust Client for Bitcoin Core API
//!
//! This is a client library for the Bitcoin Core JSON-RPC API.
//!

// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454

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
