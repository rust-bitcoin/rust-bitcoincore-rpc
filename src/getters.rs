use bitcoin::consensus::encode as btc_encode;
use bitcoin::{Script, Transaction};
use hex;

use error::Error;
use json::*;

/// Retrieve a relevant Script for the type.
pub trait GetScript {
	fn script(&self) -> Result<Script, Error>;
}

impl GetScript for GetRawTransactionResultVinScriptSig {
	fn script(&self) -> Result<Script, Error> {
		Ok(Script::from(hex::decode(&self.hex)?))
	}
}

impl GetScript for GetRawTransactionResultVoutScriptPubKey {
	fn script(&self) -> Result<Script, Error> {
		Ok(Script::from(hex::decode(&self.hex)?))
	}
}

/// Retrieve a relevant Transaction for the type.
pub trait GetTransaction {
	fn transaction(&self) -> Result<Transaction, Error>;
}

impl GetTransaction for GetRawTransactionResult {
	fn transaction(&self) -> Result<Transaction, Error> {
		Ok(btc_encode::deserialize(&hex::decode(&self.hex)?)?)
	}
}

impl GetTransaction for GetTransactionResult {
	fn transaction(&self) -> Result<Transaction, Error> {
		Ok(btc_encode::deserialize(&hex::decode(&self.hex)?)?)
	}
}

impl GetTransaction for SignRawTransactionResult {
	fn transaction(&self) -> Result<Transaction, Error> {
		Ok(btc_encode::deserialize(&hex::decode(&self.hex)?)?)
	}
}
