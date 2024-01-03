use std::{error, fmt, io};

use jsonrpc;
use serde_json;

/// The error type for errors produced in this library.
#[derive(Debug)]
pub enum Error {
    JsonRpc(jsonrpc::error::Error),
    Hex(hex::FromHexError),
    Json(serde_json::error::Error),
    Io(io::Error),
    InvalidCookieFile,
    /// The JSON result had an unexpected structure.
    UnexpectedStructure,
    /// The daemon returned an error string.
    ReturnedError(String),
    // BitcoinSVError(bitcoinsv::Error),
    MinReqError(jsonrpc::minreq_http::Error),
    SVJsonError(bitcoinsv_rpc_json::Error),
}

impl From<jsonrpc::error::Error> for Error {
    fn from(e: jsonrpc::error::Error) -> Error {
        Error::JsonRpc(e)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Error {
        Error::Hex(e)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(e: serde_json::error::Error) -> Error {
        Error::Json(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

// impl From<bitcoinsv::Error> for Error {
//     fn from(e: bitcoinsv::Error) -> Error {
//         Error::BitcoinSVError(e)
//     }
// }
//
impl From<jsonrpc::minreq_http::Error> for Error {
    fn from(e: jsonrpc::minreq_http::Error) -> Error {
        Error::MinReqError(e)
    }
}

impl From<bitcoinsv_rpc_json::Error> for Error {
    fn from(e: bitcoinsv_rpc_json::Error) -> Error {
        Error::SVJsonError(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::JsonRpc(ref e) => write!(f, "JSON-RPC error: {}", e),
            Error::Hex(ref e) => write!(f, "hex decode error: {}", e),
            Error::Json(ref e) => write!(f, "JSON error: {}", e),
            Error::Io(ref e) => write!(f, "I/O error: {}", e),
            Error::InvalidCookieFile => write!(f, "invalid cookie file"),
            Error::UnexpectedStructure => write!(f, "the JSON result had an unexpected structure"),
            Error::ReturnedError(ref s) => write!(f, "the daemon returned an error string: {}", s),
            // Error::BitcoinSVError(ref e) => write!(f, "BSV error: {}", e),
            Error::MinReqError(ref e) => write!(f, "HTTPMinReq: {}", e),
            Error::SVJsonError(ref e) => write!(f, "SVJson: {}", e),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "bitcoinsv-rpc error"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::JsonRpc(ref e) => Some(e),
            Error::Hex(ref e) => Some(e),
            Error::Json(ref e) => Some(e),
            Error::Io(ref e) => Some(e),
            _ => None,
        }
    }
}
