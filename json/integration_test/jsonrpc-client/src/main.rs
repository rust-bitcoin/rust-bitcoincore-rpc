use std::fmt;

use anyhow::Result;
use integration_test::v22::{self, BitcoindRpc};

/// Set to `true` for verbose output.
const VERBOSE: bool = true;

#[tokio::main]
async fn main() -> Result<()> {
    let username = "user";
    let password = "password";

    let url = format!("http://{}:{}@localhost:12349", username, password);
    println!("url: {}", url);

    let client = v22::Client::new(url)?;

    let res = client.getblockchaininfo().await?;
    print(res);

    let res = client.getnetworkinfo().await?;
    print(res);

    let res = client.getindexinfo().await?;
    print(res);
    
    Ok(())
}

/// Prints `res` if `VERBOSE` is set to `true`.
fn print<T: fmt::Debug>(res: T) {
    if VERBOSE {
        println!("{:#?}", res);
    }
}
