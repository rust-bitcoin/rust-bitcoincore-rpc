
use bitcoincore_rpc::{Client, AsyncClient};

#[allow(unused)]
async fn test() {
    let jsonrpc = jsonrpc::Client::with_hyper(
        hyper::Client::new(),
        "http://localhost".into(),
        Some("user".into()),
        Some("pass".into()),
    );
    let client = Client::from_jsonrpc(jsonrpc);


    let ret = client.get_blockchain_info().await.unwrap();
    println!("{}", ret.blocks);
}

fn main() {
}
