extern crate dashcore_rpc;
extern crate dashcore_rpc_json;
extern crate log;

use dashcore_rpc::{Auth, Client, RpcApi};
use dashcore_rpc_json::{ProTxListType, QuorumType};

fn main() {
    let rpc = Client::new(
        "localhost:19998",
        Auth::UserPass("dashrpc".to_string(), "password".to_string()),
    )
    .unwrap();

    // Get Dash network info
    let network_info = rpc.get_network_info().unwrap();
    println!("\nDash network info: \n{:?}", network_info);

    // Get best block hash
    let best_block_hash = rpc.get_best_block_hash().unwrap();
    println!("\n\nBest block hash: \n{}", best_block_hash);

    let best_block_hex = rpc.get_block_hex(&best_block_hash).unwrap();
    println!("\n\nBest block hex: \n{}", best_block_hex);

    let best_block_json = rpc.get_block_json(&best_block_hash).unwrap();
    println!("\n\nBest block json: \n{}", best_block_json);

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

    // Get BLS fromsecret
    let bls_fromsecret = rpc
        .get_bls_fromsecret("52f35cd3d977a505485f2474e7e71ef3f60f859603d72ad6b0fa7f7bd163e144")
        .unwrap();
    println!("\nBLS fromsecret: \n{:?}", bls_fromsecret);

    // Get BLS generate
    let bls_generate = rpc.get_bls_generate().unwrap();
    println!("\nBLS generate: \n{:?}", bls_generate);

    // Get Quorum list
    let quorum_list = rpc.get_quorum_list(None).unwrap();
    println!("\nQuorum list: \n{:?}", quorum_list);

    let quorum_hashes = quorum_list.quorums_by_type.get(&QuorumType::LlmqTest).unwrap();
    let quorum_hash = quorum_hashes.get(0);

    // Get Quorum info
    let quorum_info =
        rpc.get_quorum_info(QuorumType::LlmqTest, quorum_hash.unwrap(), None).unwrap();
    println!("\nQuorum info: \n{:?}", quorum_info);

    let quorum_listextended = rpc.get_quorum_listextended(Some(quorum_info.height)).unwrap();
    println!("\n\nQuorum list extended \n{:?}", quorum_listextended);

    let mn0 = quorum_info.members.get(0).unwrap();
    let mn0_pro_tx_hash = mn0.to_owned().pro_tx_hash;

    // Get Quorum DKG status
    let quorum_dkgstatus = rpc.get_quorum_dkgstatus(None).unwrap();
    println!("\nQuorum dkg status: \n{:?}", quorum_dkgstatus);

    // Get Quorum sign
    let quorum_sign = rpc
        .get_quorum_sign(
            QuorumType::LlmqTest,
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "51c11d287dfa85aef3eebb5420834c8e443e01d15c0b0a8e397d67e2e51aa239",
            None,
            None,
        )
        .unwrap();
    println!("\nQuorum sign: \n{:?}", quorum_sign);

    // Get Quorum GetRecSig
    // let quorum_getrecsig = rpc.get_quorum_getrecsig(
    //     QuorumType::LlmqTest,
    //     "e980ebf295b42f24b03321ffb255818753b2b211e8c46b61c0b6fde91242d12f",
    //     "907087d4720850e639b7b5cc41d7a6d020e5a50debb3bc3974f0cb3d7d378ea4",
    // ).unwrap();
    // println!("\nQuorum getrecsig: \n{:?}", quorum_getrecsig);

    // Get Quorum HasRecSig
    let quorum_hasrecsig = rpc
        .get_quorum_hasrecsig(
            QuorumType::LlmqTest,
            "e980ebf295b42f24b03321ffb255818753b2b211e8c46b61c0b6fde91242d12f",
            "907087d4720850e639b7b5cc41d7a6d020e5a50debb3bc3974f0cb3d7d378ea4",
        )
        .unwrap();
    println!("\nQuorum hasrecsig: \n{:?}", quorum_hasrecsig);

    // Get Quorum isconflicting
    let quorum_isconflicting = rpc
        .get_quorum_isconflicting(
            QuorumType::LlmqTest,
            "e980ebf295b42f24b03321ffb255818753b2b211e8c46b61c0b6fde91242d12f",
            "907087d4720850e639b7b5cc41d7a6d020e5a50debb3bc3974f0cb3d7d378ea4",
        )
        .unwrap();
    println!("\nQuorum isconflicting: \n{:?}", quorum_isconflicting);

    // Get Quorum memberof
    let quorum_memberof = rpc.get_quorum_memberof(&mn0_pro_tx_hash, Some(1)).unwrap();
    println!("\nQuorum memberof: \n{:?}", quorum_memberof);

    // Get Quorum rotationinfo
    // let quorum_rotationinfo = rpc.get_quorum_rotationinfo(
    //     block_hash,
    //     None,
    //     None,
    // ).unwrap();
    // println!("\nQuorum rotationinfo: \n{:?}", quorum_rotationinfo);

    // Get Quorum selectquorum
    // let quorum_selectquorum = rpc.get_quorum_selectquorum(
    //     QuorumType::LlmqTest,
    //     "b95205c3bba72e9edfbe7380ec91fe5a97e16a189e28f39b03c6822757ad1a34",
    // ).unwrap();
    // println!("\nQuorum selectquorum: \n{:?}", quorum_selectquorum);

    // Get Quorum verify
    // let quorum_verify = rpc.get_quorum_verify(
    //     QuorumType::LlmqTest,
    //     "2ceeaa7ff20de327ef65b14de692199d15b67b9458d0ded7d68735cce98dd039",
    //     "8b5174d0e95b5642ebec23c3fe8f0bbf8f6993502f4210322871bba0e818ff3b",
    //     "99cf2a0deb08286a2d1ffdd2564b35522fd748c8802e561abed330dea20df5cb5a5dffeddbe627ea32cb36de13d5b4a516fdfaebae9886b2f7969a5d112416cf8d1983ebcbf1463a64f7522505627e08b9c76c036616fbb1649271a2773a1653",
    //     Some(quorum_info.quorum_hash),
    //     None,
    // ).unwrap();
    // println!("\nQuorum verify: \n{:?}", quorum_verify);

    // Get Protx diff
    let protx_diff = rpc.get_protx_diff(block_count - 10, block_count).unwrap();
    println!("\nProtx diff: \n{:?}", protx_diff);

    // Get Protx info
    let protx_info = rpc.get_protx_info(&mn0_pro_tx_hash).unwrap();
    println!("\nProtx info: \n{:?}", protx_info);

    // Get Protx list
    let protx_list = rpc.get_protx_list(Some(ProTxListType::Valid), Some(true), None).unwrap();
    println!("\nProtx list: \n{:?}", protx_list);

    // Get Protx register
    // let protx_register = rpc.get_protx_register(
    //     "9a3559dc6c0ed682c475f21a5047f923e55c14dd4b8587e6052ce663ed9ee9cd",
    //     0,
    //     "192.168.65.2:20201",
    //     "yhDzUdx1MtgLnA753DLrAFtPzTeYzQ2SAP",
    //     "ab8a1a60a0cd5bbe155e91349e2341c2e2c604392e1b2738a093448011ea5adf964db13ed69beb34c4a0b73a757043fc",
    //     "yhDzUdx1MtgLnA753DLrAFtPzTeYzQ2SAP",
    //     0,
    //     "yQ5d7b8y2AP84qHFxrcpXfmXk9a8nkREpc",
    //     None,
    //     Some(false),
    // ).unwrap();
    // println!("\nProtx register: \n{:?}", protx_register);

    // Get Protx register_fund
    // let protx_register_fund = rpc.get_protx_register_fund("yakx4mMRptKhgfjedNzX5FGQq7kSSBF2e7", "3.4.5.6:3456", "yURczr3qY31xkQZfFu8eZvKz19eAEPQxsd", "0e02146e9c34cfbcb3f3037574a1abb35525e2ca0c3c6901dbf82ac591e30218d1711223b7ca956edf39f3d984d06d51", "yURczr3qY31xkQZfFu8eZvKz19eAEPQxsd", 5, "yUYTxqjpCfAAK4vgxXtBPywRBtZqsxN7Vy", Some("yRMFHxcJ2aS2vfo5whhE2Gg73dfQVm8LAF"), Some(false)).unwrap();
    // println!("\nProtx fund: \n{:?}", protx_register_fund);
}
