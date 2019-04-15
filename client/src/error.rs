// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use std::{error, fmt, io};

use bitcoin;
use hex;
use jsonrpc;
use secp256k1;
use serde_json;

/// The error type for errors produced in this library.
#[derive(Debug)]
pub enum Error {
    JsonRpc(jsonrpc::error::Error),
    FromHex(hex::FromHexError),
    Json(serde_json::error::Error),
    BitcoinSerialization(bitcoin::consensus::encode::Error),
    Secp256k1(secp256k1::Error),
    Io(io::Error),
    InvalidCookieFile,
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

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::JsonRpc(ref e) => write!(f, "JSON-RPC error: {}", e),
            Error::FromHex(ref e) => write!(f, "hex decode error: {}", e),
            Error::Json(ref e) => write!(f, "JSON error: {}", e),
            Error::BitcoinSerialization(ref e) => write!(f, "Bitcoin serialization error: {}", e),
            Error::Secp256k1(ref e) => write!(f, "secp256k1 error: {}", e),
            Error::Io(ref e) => write!(f, "I/O error: {}", e),
            ref e => f.write_str(error::Error::description(e)),
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
            Error::Secp256k1(_) => "secp256k1 error",
            Error::Io(_) => "I/O error",
            Error::InvalidCookieFile => "invalid cookie file",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::JsonRpc(ref e) => Some(e),
            Error::FromHex(ref e) => Some(e),
            Error::Json(ref e) => Some(e),
            Error::BitcoinSerialization(ref e) => Some(e),
            Error::Secp256k1(ref e) => Some(e),
            Error::Io(ref e) => Some(e),
            _ => None,
        }
    }
}
