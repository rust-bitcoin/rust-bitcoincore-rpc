extern crate dashcore_rpc;

use dashcore_rpc::{Auth, Client, RpcApi};

fn main() {
    let rpc = Client::new(
        "localhost:19998",
        Auth::UserPass("dashrpc".to_string(), "rpcpassword".to_string()),
    )
    .unwrap();

    // Get Dash network info
    let network_info = rpc.get_network_info().unwrap();
    println!("\nDash network info: \n{:?}", network_info);

    // Get best block hash
    let best_block_hash = rpc.get_best_block_hash().unwrap();
    println!("\n\nBest block hash: \n{}", best_block_hash);

    // Get block count
    let block_count = rpc.get_block_count().unwrap();
    println!("\n\nBlock count: \n{}", block_count);

    // Get block hash (for the a specified block height)
    let block_hash = rpc.get_block_hash(block_count).unwrap();
    println!("\n\nBlock hash at block height {}: \n{}", block_count, block_hash);

    // Get masternode count
    let masternode_count = rpc.get_masternode_count().unwrap();
    println!("\n\nMasternode Count: \n{:?}", masternode_count);


    // Get masternode list
    let mn_list = rpc.get_masternode_list(Some("json"), None).unwrap();
    println!("\n\nMasternode List: \n{:?}", mn_list);

    // Get masternode outputs
    let mn_outputs = rpc.get_masternode_outputs().unwrap();
    println!("\n\nMasternode Outputs: \n{:?}", mn_outputs);

    // Get masternode payments 
    let mn_payments = rpc.get_masternode_payments(None, None).unwrap();
    println!("\n\nMasternode Payments: \n{:?}", mn_payments);

    // Get masternode status
    let mn_status = rpc.get_masternode_status().unwrap();
    println!("\n\nMasternode Status: \n{:?}", mn_status);

    // Get masternode winners
    let mn_winners = rpc.get_masternode_winners(None, None).unwrap();
    println!("\n\nMasternode Winners: \n{:?}", mn_winners);

    // Get Quorum list
    let quorum_list = rpc.get_quorum_list(None).unwrap();
    println!("\nQuorum list: \n{:?}", quorum_list);

    // Get Quorum info
    let quorum_info = rpc.get_quorum_info(1, "000000000c9eddd5d2a707281b7e30d5aac974dac600ff10f01937e1ca36066f", None).unwrap();
    println!("\nQuorum info: \n{:?}", quorum_info);

    // Get Quorum DKG status
    let quorum_dkgstatus = rpc.get_quorum_dkgstatus(None).unwrap();
    println!("\nQuorum dkg status: \n{:?}", quorum_dkgstatus);

    // Get Quorum sign
    let quorum_sign = rpc.get_quorum_sign(1, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234", "51c11d287dfa85aef3eebb5420834c8e443e01d15c0b0a8e397d67e2e51aa239", None, None).unwrap();
    println!("\nQuorum sign: \n{:?}", quorum_sign);

    // Get Quorum GetRecSig
    let quorum_getrecsig = rpc.get_quorum_getrecsig(1, "e980ebf295b42f24b03321ffb255818753b2b211e8c46b61c0b6fde91242d12f", "907087d4720850e639b7b5cc41d7a6d020e5a50debb3bc3974f0cb3d7d378ea4").unwrap();
    println!("\nQuorum getrecsig: \n{:?}", quorum_getrecsig);
}
