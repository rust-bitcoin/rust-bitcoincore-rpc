//! # Rust Client for Bitcoin Core API
//!
//! This is a client library for the Bitcoin Core JSON-RPC API.
//!

#![crate_name = "bitcoincore_rpc"]
#![crate_type = "rlib"]

#[macro_use]
extern crate log;
extern crate bitcoin;
extern crate bitcoin_amount;
extern crate hex;
extern crate jsonrpc;
extern crate num_bigint;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;

pub extern crate bitcoincore_rpc_json;
pub use bitcoincore_rpc_json as json;

mod client;
mod error;
mod getters;

pub use client::*;
pub use error::Error;
pub use getters::*;
