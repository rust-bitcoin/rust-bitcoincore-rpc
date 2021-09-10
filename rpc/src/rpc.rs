//! Simple RPC client implementation which implements [`BlockSource`] against a Bitcoin Core RPC
//! endpoint.

use crate::http::{Error, HttpClient, HttpEndpoint, HttpError, JsonResponse, RpcError};

use base64;
use serde_json;

use std::cell::RefCell;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A simple RPC client for calling methods using HTTP `POST`.
#[derive(Debug)]
pub struct RpcClient {
    basic_auth: String,
    endpoint: HttpEndpoint,
    client: Rc<RefCell<HttpClient>>,
    id: AtomicUsize,
}

impl RpcClient {
    /// Creates a new RPC client connected to the given endpoint with the provided credentials. The
    /// credentials should be a base64 encoding of a user name and password joined by a colon, as is
    /// required for HTTP basic access authentication.
    pub fn new(
        user: Option<String>,
        password: Option<String>,
        endpoint: HttpEndpoint,
    ) -> std::io::Result<Self> {
        let client = HttpClient::connect(&endpoint)?;

        let basic_auth = match (user, password) {
            (Some(u), Some(p)) => "Basic ".to_string() + &base64::encode(format!("{}:{}", u, p)),
            _ => "Basic ".to_string(),
        };

        Ok(Self {
            basic_auth,
            endpoint,
            client: Rc::new(RefCell::new(client)),
            id: AtomicUsize::new(0),
        })
    }

    pub fn from_url(
        user: Option<String>,
        password: Option<String>,
        url: &str,
    ) -> std::io::Result<Self> {
        let endpoint = HttpEndpoint::from_url(url)?;
        Self::new(user, password, endpoint)
    }

    /// Calls a method with the response encoded in JSON format and interpreted as type `T`.
    pub async fn call_method<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> Result<T, Error> {
        let host = format!("{}:{}", self.endpoint.host(), self.endpoint.port());
        let uri = self.endpoint.path();
        let content = serde_json::json!({
            "method": method,
            "params": params,
            "id": &self.id.fetch_add(1, Ordering::AcqRel).to_string()
        });

        let mut response = match self
            .client
            .borrow_mut()
            .post::<JsonResponse>(&uri, &host, &self.basic_auth, content)
            .await
        {
            Ok(JsonResponse(response)) => response,
            Err(e) if e.kind() == std::io::ErrorKind::Other => {
                match e.get_ref().unwrap().downcast_ref::<HttpError>() {
                    Some(http_error) => match JsonResponse::try_from(http_error.contents.clone()) {
                        Ok(JsonResponse(response)) => response,
                        Err(_) => Err(e)?,
                    },
                    None => Err(e)?,
                }
            }
            Err(e) => Err(e)?,
        };

        if !response.is_object() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected JSON object",
            )));
        }

        let error = &response["error"];
        if !error.is_null() {
            let message = error["message"].as_str().unwrap_or("unknown error").to_string();
            return Err(Error::Rpc(RpcError::new(
                i32::try_from(error["code"].as_i64().unwrap()).unwrap(),
                message,
            )));
        }

        let result = &mut response["result"];
        if result.is_null() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected JSON result",
            )));
        }

        serde_json::from_value(result.clone()).map_err(|e| Error::Json(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_tests::{HttpServer, MessageBody};

    /// Credentials
    const USER: &'static str = "user";
    const PASS: &'static str = "password";

    #[tokio::test]
    async fn call_method_returning_unknown_response() {
        let server = HttpServer::responding_with_not_found();
        let client =
            RpcClient::new(Some(USER.into()), Some(PASS.into()), server.endpoint()).unwrap();

        match client.call_method::<u64>("getblockcount", &[]).await {
            Err(e) => match e {
                Error::Io(io_e) => assert_eq!(io_e.kind(), std::io::ErrorKind::Other),
                _ => panic!("Expected IO Error"),
            },
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn call_method_returning_malformed_response() {
        let response = serde_json::json!("foo");
        let server = HttpServer::responding_with_ok(MessageBody::Content(response));
        let client =
            RpcClient::new(Some(USER.into()), Some(PASS.into()), server.endpoint()).unwrap();

        match client.call_method::<u64>("getblockcount", &[]).await {
            Err(e) => match e {
                Error::Io(io_e) => {
                    assert_eq!(io_e.kind(), std::io::ErrorKind::InvalidData);
                    assert_eq!(io_e.get_ref().unwrap().to_string(), "expected JSON object");
                }
                _ => panic!("Expected IO Error"),
            },
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn call_method_returning_error() {
        let errno = -8;
        let errmsg = "invalid parameter";

        let response = serde_json::json!({
            "error": { "code": errno.clone(), "message": errmsg.clone() },
        });
        let server = HttpServer::responding_with_server_error(response);
        let client =
            RpcClient::new(Some(USER.into()), Some(PASS.into()), server.endpoint()).unwrap();

        let invalid_block_hash = serde_json::json!("foo");
        match client.call_method::<u64>("getblock", &[invalid_block_hash]).await {
            Err(e) => match e {
                Error::Rpc(rpc_e) => {
                    assert_eq!(rpc_e.code, errno);
                    assert_eq!(rpc_e.message, errmsg);
                }
                _ => panic!("Expected RPC Error"),
            },
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn call_method_returning_missing_result() {
        let response = serde_json::json!({ "result": null });
        let server = HttpServer::responding_with_ok(MessageBody::Content(response));
        let client =
            RpcClient::new(Some(USER.into()), Some(PASS.into()), server.endpoint()).unwrap();

        match client.call_method::<u64>("getblockcount", &[]).await {
            Err(e) => match e {
                Error::Io(io_e) => {
                    assert_eq!(io_e.kind(), std::io::ErrorKind::InvalidData);
                    assert_eq!(io_e.get_ref().unwrap().to_string(), "expected JSON result");
                }
                _ => panic!("Expected IO Error"),
            },
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn call_method_returning_malformed_result() {
        let data = "foo";
        let response = serde_json::json!({ "result": data.clone() });
        let server = HttpServer::responding_with_ok(MessageBody::Content(response));
        let client =
            RpcClient::new(Some(USER.into()), Some(PASS.into()), server.endpoint()).unwrap();

        match client.call_method::<u64>("getblockcount", &[]).await {
            Err(e) => match e {
                Error::Json(json_e) => {
                    assert_eq!(
                        json_e.to_string(),
                        format!("invalid type: string \"{}\", expected u64", data)
                    );
                }
                _ => panic!("Expected IO Error"),
            },
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn call_method_returning_valid_result() {
        let response = serde_json::json!({ "result": 654470 });
        let server = HttpServer::responding_with_ok(MessageBody::Content(response));
        let client =
            RpcClient::new(Some(USER.into()), Some(PASS.into()), server.endpoint()).unwrap();

        match client.call_method::<u64>("getblockcount", &[]).await {
            Err(e) => panic!("Unexpected error: {:?}", e),
            Ok(count) => assert_eq!(count, 654470),
        }
    }
}
