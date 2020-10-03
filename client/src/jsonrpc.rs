use crate::{Error, JsonRpcError};
use serde::{Deserialize, Serialize};
use serde_json;

/// Types re-declared from [rust-jsonrpc](https://github.com/apoelstra/rust-jsonrpc/blob/master/src/lib.rs)

#[derive(Debug, Clone, PartialEq, Serialize)]
/// A JSONRPC request object
pub struct JsonRpcRequest<'a, 'b> {
    /// The name of the RPC call
    pub method: &'a str,
    /// Parameters to the RPC call
    pub params: &'b [serde_json::Value],
    /// Identifier for this Request, which should appear in the response
    pub id: serde_json::Value,
    /// jsonrpc field, MUST be "2.0"
    pub jsonrpc: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
/// A JSONRPC response object
pub struct JsonRpcResponse {
    /// A result if there is one, or null
    pub result: Option<serde_json::Value>,
    /// An error if there is one, or null
    pub error: Option<JsonRpcError>,
    /// Identifier for this Request, which should match that of the request
    pub id: serde_json::Value,
    /// jsonrpc field, MUST be "2.0"
    pub jsonrpc: Option<String>,
}

impl JsonRpcResponse {
    pub fn into_result<T: serde::de::DeserializeOwned>(self) -> Result<T, Error> {
        if let Some(e) = self.error {
            return Err(Error::JsonRpc(e));
        }

        serde_json::from_value(self.result.unwrap_or(serde_json::Value::Null)).map_err(Error::Json)
    }
}
