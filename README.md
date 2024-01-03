

# Rust RPC client for Bitcoin SV JSON-RPC 
![Unit Test Status](https://gist.githubusercontent.com/Danconnolly/9154c08943fa65569d4307fd1a2ab461/raw/badge.svg)

This is a Rust RPC Client Library for calling the Bitcoin SV JSON-RPC API. 

This repository contains two published crates: bitcoinsv-rpc and bitcoinsv-rpc-json. 
The former contains an implementation of an rpc client that exposes the Bitcoin SV JSON-RPC APIs as rust functions. 
The latter contains rust data structures that represent the json responses from the Bitcoin SV JSON-RPC APIs. 

Normally you will just use the bitcoinsv-rpc crate, which depends on the bitcoinsv-rpc-json crate.

# Usage
Given below is an example of how to connect to the Bitcoin SV JSON-RPC for a Bitcoin SV node running on `localhost`
and print out the hash of the latest block.

It assumes that the node has password authentication setup, the RPC interface is enabled at port `8332` and the node
is set up to accept RPC connections. 

```rust
extern crate bitcoinsv_rpc;

use bitcoinsv_rpc::{Auth, Client, RpcApi};

fn main() {

    let rpc = Client::new("http://localhost:8332",
                          Auth::UserPass("<FILL RPC USERNAME>".to_string(),
                                         "<FILL RPC PASSWORD>".to_string())).unwrap();
    let best_block_hash = rpc.get_best_block_hash().unwrap();
    println!("best block hash: {}", best_block_hash);
}
```

See `client/examples/` for more usage examples. 

# Supported Bitcoin SV Versions
The following versions are officially supported and automatically tested:
* 1.0.16

# SV Nodes
Users and developers are not encouraged to run a Bitcoin SV Node. SPV and LiteClient technologies should be used
to interact with the Bitcoin SV network. However, many of these technologies are still in development and some
developers may need to run a Bitcoin SV node, preferably in pruned mode. This library as been provided for these users,
as well as for miners.

Coming soon, a prometheus exporter for Bitcoin SV nodes that will use these libraries.
