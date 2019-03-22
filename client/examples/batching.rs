// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

extern crate bitcoin;
extern crate bitcoincore_rpc;

use bitcoincore_rpc::{Client, Error};

fn main_result() -> Result<(), Error> {
    let url = "http://localhost:18332/".to_owned();
    let user = Some("rpcuser".to_owned());
    let pass = Some("rpcpass".to_owned());

    let rpc = Client::new(url, user, pass);

    let mut batch = rpc.start_batch();

    let blockchain_info = batch.get_blockchain_info()?;
    let best_block_hash = batch.get_best_block_hash()?;
    let best_block_count = batch.get_block_count()?;

    println!("result ready: {}", blockchain_info.ready());
    batch.execute()?;
    println!("result ready: {}", blockchain_info.ready());

    println!("chain: {}", blockchain_info.take()?.chain);
    println!("best block hash: {}", best_block_hash.take()?);
    println!("best block height: {}", best_block_count.take()?);

    Ok(())
}

fn main() {
    main_result().unwrap();
}
