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
use std::error;

use bitcoin::consensus::encode as btc_encode;
use bitcoin::{Script, Transaction};
use hex;

use super::*;

/// The error type for errors produced in this library.
#[derive(Debug)]
pub enum GetterError {
    FromHex(hex::FromHexError),
    BitcoinSerialization(bitcoin::consensus::encode::Error),
}

impl From<hex::FromHexError> for GetterError {
    fn from(e: hex::FromHexError) -> GetterError {
        GetterError::FromHex(e)
    }
}

impl From<bitcoin::consensus::encode::Error> for GetterError {
    fn from(e: bitcoin::consensus::encode::Error) -> GetterError {
        GetterError::BitcoinSerialization(e)
    }
}

impl fmt::Display for GetterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GetterError::FromHex(ref e) => write!(f, "hex decode error: {}", e),
            GetterError::BitcoinSerialization(ref e) => write!(f, "Bitcoin serialization error: {}", e),
        }
    }
}

impl error::Error for GetterError {
    fn description(&self) -> &str {
        match *self {
            GetterError::FromHex(_) => "hex decode error",
            GetterError::BitcoinSerialization(_) => "Bitcoin serialization error",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            GetterError::FromHex(ref e) => Some(e),
            GetterError::BitcoinSerialization(ref e) => Some(e),
        }
    }
}

/// Retrieve a relevant Script for the type.
pub trait GetScript {
    fn script(&self) -> Result<Script, GetterError>;
}

impl GetScript for GetRawTransactionResultVinScriptSig {
    fn script(&self) -> Result<Script, GetterError> {
        Ok(Script::from(hex::decode(&self.hex)?))
    }
}

impl GetScript for GetRawTransactionResultVoutScriptPubKey {
    fn script(&self) -> Result<Script, GetterError> {
        Ok(Script::from(hex::decode(&self.hex)?))
    }
}

/// Retrieve a relevant Transaction for the type.
pub trait GetTransaction {
    fn transaction(&self) -> Result<Transaction, GetterError>;
}

impl GetTransaction for GetRawTransactionResult {
    fn transaction(&self) -> Result<Transaction, GetterError> {
        Ok(btc_encode::deserialize(&hex::decode(&self.hex)?)?)
    }
}

impl GetTransaction for GetTransactionResult {
    fn transaction(&self) -> Result<Transaction, GetterError> {
        Ok(btc_encode::deserialize(&hex::decode(&self.hex)?)?)
    }
}

impl GetTransaction for SignRawTransactionResult {
    fn transaction(&self) -> Result<Transaction, GetterError> {
        Ok(btc_encode::deserialize(&hex::decode(&self.hex)?)?)
    }
}
