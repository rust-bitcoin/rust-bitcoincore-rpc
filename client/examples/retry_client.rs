// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use async_trait::async_trait;
use bitcoincore_rpc;
use serde;
use serde_json;

use bitcoincore_rpc::{Client, Error, Result, RpcApi};

pub struct RetryClient {
    client: Client,
}

const INTERVAL: u64 = 1000;
const RETRY_ATTEMPTS: u8 = 10;

#[async_trait]
impl RpcApi for RetryClient {
    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        for _ in 0..RETRY_ATTEMPTS {
            match self.client.call(cmd, args).await {
                Ok(ret) => return Ok(ret),
                Err(Error::JsonRpc(ref rpcerr)) if rpcerr.code == -28 => {
                    ::std::thread::sleep(::std::time::Duration::from_millis(INTERVAL));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        self.client.call(cmd, args).await
    }
}

fn main() {}
