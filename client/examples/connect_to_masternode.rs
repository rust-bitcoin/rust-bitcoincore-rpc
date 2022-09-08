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

    // Get Quorum HasRecSig
    let quorum_hasrecsig = rpc.get_quorum_hasrecsig(1, "e980ebf295b42f24b03321ffb255818753b2b211e8c46b61c0b6fde91242d12f", "907087d4720850e639b7b5cc41d7a6d020e5a50debb3bc3974f0cb3d7d378ea4").unwrap();
    println!("\nQuorum hasrecsig: \n{:?}", quorum_hasrecsig);

    // Get Quorum isconflicting
    let quorum_isconflicting = rpc.get_quorum_isconflicting(1, "e980ebf295b42f24b03321ffb255818753b2b211e8c46b61c0b6fde91242d12f", "907087d4720850e639b7b5cc41d7a6d020e5a50debb3bc3974f0cb3d7d378ea4").unwrap();
    println!("\nQuorum isconflicting: \n{:?}", quorum_isconflicting);

    // Get Quorum memberof
    let quorum_memberof = rpc.get_quorum_memberof("39c07d2c9c6d0ead56f52726b63c15e295cb5c3ecf7fe1fefcfb23b2e3cfed1f", Some(1)).unwrap();
    println!("\nQuorum memberof: \n{:?}", quorum_memberof);

    // Get Quorum rotationinfo
    let quorum_rotationinfo = rpc.get_quorum_rotationinfo("0000012197b7ca6360af3756c6a49c217dbbdf8b595fd55e0fcef7ffcd546044", None, None).unwrap();
    println!("\nQuorum rotationinfo: \n{:?}", quorum_rotationinfo);

    // Get Quorum selectquorum
    let quorum_selectquorum = rpc.get_quorum_selectquorum(1, "b95205c3bba72e9edfbe7380ec91fe5a97e16a189e28f39b03c6822757ad1a34").unwrap();
    println!("\nQuorum selectquorum: \n{:?}", quorum_selectquorum);

    // Get Quorum verify
    let quorum_verify = rpc.get_quorum_verify(1, "2ceeaa7ff20de327ef65b14de692199d15b67b9458d0ded7d68735cce98dd039", "8b5174d0e95b5642ebec23c3fe8f0bbf8f6993502f4210322871bba0e818ff3b", "99cf2a0deb08286a2d1ffdd2564b35522fd748c8802e561abed330dea20df5cb5a5dffeddbe627ea32cb36de13d5b4a516fdfaebae9886b2f7969a5d112416cf8d1983ebcbf1463a64f7522505627e08b9c76c036616fbb1649271a2773a1653", Some("000000583a348d1a0a5f753ef98e6a69f9bcd9b27919f10eb1a1c3edb6c79182"), None).unwrap();
    println!("\nQuorum verify: \n{:?}", quorum_verify);

    // Get Protx diff
    let protx_diff = rpc.get_protx_diff(75000, 76000).unwrap();
    println!("\nProtx diff: \n{:?}", protx_diff);
}
