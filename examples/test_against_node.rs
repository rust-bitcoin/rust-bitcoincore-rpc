//! A very simple example used as a self-test of this library against a Bitcoin
//! Core node.
extern crate bitcoin;
extern crate bitcoindrpc;
#[macro_use]
extern crate failure;

use bitcoindrpc::Client;

type Result<T> = std::result::Result<T, failure::Error>;

fn main() -> Result<()> {
	let mut args = std::env::args();

	let _exe_name = args.next().unwrap();

	let url = args.next().ok_or_else(|| format_err!("Usage: <rpc_url> [username] [password]"))?;
	let user = args.next();
	let pass = args.next();

	let mut rpc = Client::new(url, user, pass);

	let _blockchain_info = rpc.getblockchaininfo()?;

	let best_block_hash = rpc.getbestblockhash()?;
	println!("best block hash: {}", best_block_hash);
	let bestblockcount = rpc.getblockcount()?;
	println!("best block height: {}", bestblockcount);
	let best_block_hash_by_height = rpc.getblockhash(bestblockcount)?;
	println!("best block hash by height: {}", best_block_hash_by_height);
	assert_eq!(best_block_hash_by_height, best_block_hash);

	let bitcoin_block: bitcoin::Block = rpc.get_by_id(&best_block_hash)?;
	println!("best block hash by `get`: {}", bitcoin_block.header.prev_blockhash);
	let bitcoin_tx: bitcoin::Transaction = rpc.get_by_id(&bitcoin_block.txdata[0].txid())?;
	println!("tx by `get`: {}", bitcoin_tx.txid());

	Ok(())
}
