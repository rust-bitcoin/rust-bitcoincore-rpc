// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic;

use jsonrpc;
use log::Level::{Debug, Trace, Warn};
use serde_json;

use crate::{Error, Result};

/// The different authentication methods for the client.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum Auth {
    None,
    UserPass(String, String),
    CookieFile(PathBuf),
}

impl Auth {
    /// Convert into the arguments that jsonrpc::Client needs.
    pub fn get_user_pass(self) -> Result<(Option<String>, Option<String>)> {
        match self {
            Auth::None => Ok((None, None)),
            Auth::UserPass(u, p) => Ok((Some(u), Some(p))),
            Auth::CookieFile(path) => {
                let mut file = File::open(path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let mut split = contents.splitn(2, ":");
                Ok((
                    Some(split.next().ok_or(Error::InvalidCookieFile)?.into()),
                    Some(split.next().ok_or(Error::InvalidCookieFile)?.into()),
                ))
            }
        }
    }
}

/// Client implements a JSON-RPC client for the Bitcoin Core daemon or compatible APIs.
pub struct Client<T> {
    pub(crate) client: jsonrpc::Client<T>,
    pub(crate) version: atomic::AtomicUsize,
}

impl<T: fmt::Debug> fmt::Debug for Client<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bitcoincore_rpc::Client({:?})", self.client)
    }
}

impl<T> Client<T> {
    /// Create a new Client using the given [jsonrpc::Client].
    pub fn from_jsonrpc(client: jsonrpc::Client<T>) -> Client<T> {
        Client {
            client,
            version: atomic::AtomicUsize::new(0),
        }
    }

    /// Get the underlying JSONRPC client.
    pub fn jsonrpc_client(&self) -> &jsonrpc::Client<T> {
        &self.client
    }
}

impl Client<jsonrpc::simple_http::SimpleHttpTransport> {
    /// Creates a client to a bitcoind JSON-RPC server.
    ///
    /// Can only return [Err] when using cookie authentication.
    pub fn with_simple_http(url: &str, auth: Auth) -> Result<Self> {
        let (user, pass) = auth.get_user_pass()?;
        jsonrpc::Client::with_simple_http(url, user, pass)
            .map(|client| Client {
                client: client,
                version: atomic::AtomicUsize::new(0),
            })
            .map_err(|e| super::error::Error::JsonRpc(e.into()))
    }
}

fn log_response(cmd: &str, resp: &Result<jsonrpc::json::Response>) {
    if log_enabled!(Warn) || log_enabled!(Debug) || log_enabled!(Trace) {
        match resp {
            Err(ref e) => {
                if log_enabled!(Debug) {
                    debug!(target: "bitcoincore_rpc", "JSON-RPC failed parsing reply of {}: {:?}", cmd, e);
                }
            }
            Ok(ref resp) => {
                if let Some(ref e) = resp.error {
                    if log_enabled!(Debug) {
                        debug!(target: "bitcoincore_rpc", "JSON-RPC error for {}: {:?}", cmd, e);
                    }
                } else if log_enabled!(Trace) {
                    // we can't use to_raw_value here due to compat with Rust 1.29
                    let def = serde_json::value::RawValue::from_string(
                        serde_json::Value::Null.to_string(),
                    )
                    .unwrap();
                    let result = resp.result.as_ref().unwrap_or(&def);
                    trace!(target: "bitcoincore_rpc", "JSON-RPC response for {}: {}", cmd, result);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SyncClient;
    use crate::bitcoin;
    use crate::bitcoin::hashes::hex::FromHex;

    #[test]
    fn test_raw_tx() {
        use crate::bitcoin::consensus::encode;
        let client = Client::with_simple_http("http://localhost/".into(), Auth::None).unwrap();
        let tx: bitcoin::Transaction = encode::deserialize(&Vec::<u8>::from_hex("0200000001586bd02815cf5faabfec986a4e50d25dbee089bd2758621e61c5fab06c334af0000000006b483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2dfeffffff021dc4260c010000001976a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac00e1f505000000001976a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88acfd211500").unwrap()).unwrap();

        assert!(client.send_raw_transaction(&tx).is_err());
        assert!(client.send_raw_transaction(&encode::serialize(&tx)).is_err());
        assert!(client.send_raw_transaction("deadbeef").is_err());
        assert!(client.send_raw_transaction(&"deadbeef".to_owned()).is_err());
    }
}
