use std::error;
use std::fmt;

use bitcoin;
use hex;
use jsonrpc;
use serde_json;

/// The error type for errors produced in this library.
#[derive(Debug)]
pub enum Error {
	JsonRpc(jsonrpc::error::Error),
	FromHex(hex::FromHexError),
	Json(serde_json::error::Error),
	BitcoinSerialization(bitcoin::consensus::encode::Error),
}

impl From<jsonrpc::error::Error> for Error {
	fn from(e: jsonrpc::error::Error) -> Error {
		Error::JsonRpc(e)
	}
}

impl From<hex::FromHexError> for Error {
	fn from(e: hex::FromHexError) -> Error {
		Error::FromHex(e)
	}
}

impl From<serde_json::error::Error> for Error {
	fn from(e: serde_json::error::Error) -> Error {
		Error::Json(e)
	}
}

impl From<bitcoin::consensus::encode::Error> for Error {
	fn from(e: bitcoin::consensus::encode::Error) -> Error {
		Error::BitcoinSerialization(e)
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Error::JsonRpc(ref e) => write!(f, "JSON-RPC error: {}", e),
			Error::FromHex(ref e) => write!(f, "hex decode error: {}", e),
			Error::Json(ref e) => write!(f, "JSON error: {}", e),
			Error::BitcoinSerialization(ref e) => write!(f, "Bitcoin serialization error: {}", e),
		}
	}
}

impl error::Error for Error {
	fn description(&self) -> &str {
		match *self {
			Error::JsonRpc(_) => "JSON-RPC error",
			Error::FromHex(_) => "hex decode error",
			Error::Json(_) => "JSON error",
			Error::BitcoinSerialization(_) => "Bitcoin serialization error",
		}
	}

	fn cause(&self) -> Option<&error::Error> {
		match *self {
			Error::JsonRpc(ref e) => Some(e),
			Error::FromHex(ref e) => Some(e),
			Error::Json(ref e) => Some(e),
			Error::BitcoinSerialization(ref e) => Some(e),
		}
	}
}
