// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use bitcoin::consensus::encode as btc_encode;
use bitcoin::{Script, Transaction};
use hex;

use error::Error;
use json;

/// Retrieve a relevant Script for the type.
pub trait GetScript {
    fn script(&self) -> Result<Script, Error>;
}

impl GetScript for json::GetRawTransactionResultVinScriptSig {
    fn script(&self) -> Result<Script, Error> {
        Ok(Script::from(hex::decode(&self.hex)?))
    }
}

impl GetScript for json::GetRawTransactionResultVoutScriptPubKey {
    fn script(&self) -> Result<Script, Error> {
        Ok(Script::from(hex::decode(&self.hex)?))
    }
}

/// Retrieve a relevant Transaction for the type.
pub trait GetTransaction {
    fn transaction(&self) -> Result<Transaction, Error>;
}

impl GetTransaction for json::GetRawTransactionResult {
    fn transaction(&self) -> Result<Transaction, Error> {
        Ok(btc_encode::deserialize(&hex::decode(&self.hex)?)?)
    }
}

impl GetTransaction for json::GetTransactionResult {
    fn transaction(&self) -> Result<Transaction, Error> {
        Ok(btc_encode::deserialize(&hex::decode(&self.hex)?)?)
    }
}

impl GetTransaction for json::SignRawTransactionResult {
    fn transaction(&self) -> Result<Transaction, Error> {
        Ok(btc_encode::deserialize(&hex::decode(&self.hex)?)?)
    }
}
