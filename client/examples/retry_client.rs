extern crate bitcoinsv_rpc;
extern crate jsonrpc;
extern crate serde;
extern crate serde_json;

use bitcoinsv_rpc::{Client, Error, Result, RpcApi};

pub struct RetryClient {
    client: Client,
}

const INTERVAL: u64 = 1000;
const RETRY_ATTEMPTS: u8 = 10;

impl RpcApi for RetryClient {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        for _ in 0..RETRY_ATTEMPTS {
            match self.client.call(cmd, args) {
                Ok(ret) => return Ok(ret),
                Err(Error::JsonRpc(jsonrpc::error::Error::Rpc(ref rpcerr)))
                    if rpcerr.code == -28 =>
                {
                    ::std::thread::sleep(::std::time::Duration::from_millis(INTERVAL));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        self.client.call(cmd, args)
    }
}

fn main() {}
