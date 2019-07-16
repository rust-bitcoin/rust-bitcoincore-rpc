extern crate bitcoin_amount;
extern crate bitcoincore_rpc;
extern crate dirs;

fn main() {
    use bitcoin_amount::Amount;
    use bitcoincore_rpc::{Auth, Client, RpcApi};

    let mut cookie = dirs::home_dir().unwrap();
    cookie.push(".bitcoin/regtest/.cookie");

    let client = Client::new(
        "http://127.0.0.1:18443".into(),
        Auth::CookieFile(cookie)
    ).expect("built bitcoind client");

    let addr = client.get_new_address(None, None).expect("new address");
    client.generate_to_address(1, &addr).expect("gimme coinz");
    client.generate(101, None).expect("reach maturity");

    let balance = client.get_received_by_address(&addr, None).expect("check balance");

    assert_eq!(balance, Amount::from_btc(50.0));
}