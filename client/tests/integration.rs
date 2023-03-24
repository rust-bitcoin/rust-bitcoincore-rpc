extern crate bitcoincore_rpc;
extern crate bitcoind;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoind::{downloaded_exe_path, BitcoinD};

fn init() -> (Client, BitcoinD) {
    let exe = std::env::var("BITCOIND_EXE")
        .ok()
        .or(downloaded_exe_path())
        .expect("BITCOIND_EXE or bitcoind version feature must be specified");
    let bitcoind = bitcoind::BitcoinD::new(exe).unwrap();
    let auth = Auth::CookieFile(bitcoind.params.cookie_file.clone());
    let cl = Client::new(bitcoind.rpc_url(), auth).unwrap();

    (cl, bitcoind)
}

#[test]
fn test_get_blockchain_info() {
    let (cl, _bitcoind) = init();
    let info = cl.get_blockchain_info().unwrap();
    assert_eq!(&info.chain, "regtest");
}
