# Rust RPC client for Bitcoin Core JSON-RPC 

This crate is explicitly provided for integration testing, it is not designed to be used in production systems.

This is a Rust RPC client library for calling the Bitcoin Core JSON-RPC API. It provides a layer of abstraction over 
[rust-jsonrpc](https://github.com/apoelstra/rust-jsonrpc) and makes it easier to talk to the Bitcoin JSON-RPC interface.

`rust-jsonrpc` will never be `async`, therefore neither will this crate.

This git package compiles into two crates.
1. `core-rpc` - contains an implementation of an rpc client that exposes the Bitcoin Core JSON-RPC APIs as rust functions.

2. `core-rpc-json` -  contains rust data structures that represent the json responses from the
   Bitcoin Core JSON-RPC APIs. bitcoincore-rpc depends on this.

# Usage

Given below is an example of how to connect to the Bitcoin Core JSON-RPC for a Bitcoin Core node running on `localhost`
and print out the hash of the latest block.

It assumes that the node has password authentication setup, the RPC interface is enabled at port `8332` and the node
is set up to accept RPC connections. 

```rust
extern crate bitcoincore_rpc;

use bitcoincore_rpc::{Auth, Client, RpcApi};

fn main() {

    let rpc = Client::new("http://localhost:8332",
                          Auth::UserPass("<FILL RPC USERNAME>".to_string(),
                                         "<FILL RPC PASSWORD>".to_string())).unwrap();
    let best_block_hash = rpc.get_best_block_hash().unwrap();
    println!("best block hash: {}", best_block_hash);
}
```

See `client/examples/` for more usage examples. 

# Supported Bitcoin Core Versions

The following versions are officially supported and automatically tested:
* 0.18.0
* 0.18.1
* 0.19.0.1
* 0.19.1
* 0.20.0
* 0.20.1
* 0.21.0

# Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features on **Rust 1.56.1**.
