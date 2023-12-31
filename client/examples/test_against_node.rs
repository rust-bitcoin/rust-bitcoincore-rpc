//! A very simple example used as a self-test of this library against a Bitcoin
//! SV node.
extern crate bitcoinsv_rpc;

use sv::messages::Block;
use bitcoinsv_rpc::{Auth, Client, Error, RpcApi};

fn main_result() -> Result<(), Error> {
    let mut args = std::env::args();

    let _exe_name = args.next().unwrap();

    let url = args.next().expect("Usage: <rpc_url> <username> <password>");
    let user = args.next().expect("no user given");
    let pass = args.next().expect("no pass given");

    let rpc = Client::new(&url, Auth::UserPass(user, pass)).unwrap();

    let _blockchain_info = rpc.get_blockchain_info()?;

    let best_block_hash = rpc.get_best_block_hash()?;
    println!("best block hash: {}", best_block_hash);
    let bestblockcount = rpc.get_block_count()?;
    println!("best block height: {}", bestblockcount);
    let best_block_hash_by_height = rpc.get_block_hash(bestblockcount)?;
    println!("best block hash by height: {}", best_block_hash_by_height);
    assert_eq!(best_block_hash_by_height, best_block_hash);
    let bitcoin_block: Block = rpc.get_block(&best_block_hash)?;
    println!("best block hash by `get`: {:?}", bitcoin_block.header.hash());
    Ok(())
}

fn main() {
    main_result().unwrap();
}
