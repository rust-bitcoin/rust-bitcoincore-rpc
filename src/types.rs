
use std::str::FromStr;

use hex;
use serde;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::util::address::Address;
use bitcoin::consensus::encode as btc_encode;
use bitcoin::util::hash::Sha256dHash;
use bitcoin_amount::Amount;
use num_bigint::BigUint;
use serde::de::Error as SerdeError;
use serde::Deserialize;

use error::Error;

macro_rules! bitcoin_hex {
	(Script, $hex:expr) => {
		Ok(Script::from(hex::decode($hex)?))
	};
	($raw_type:ty, $hex:expr) => {
		btc_encode::deserialize(hex::decode($hex)?.as_slice()).map_err(Error::from)
	};
}


#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockResult {
	pub hash: Sha256dHash,
	pub confirmations: usize,
	pub size: usize,
	pub strippedsize: Option<usize>,
	pub weight: usize,
	pub height: usize,
	pub version: u32,
	pub version_hex: Option<String>,
	pub merkleroot: Sha256dHash,
	pub tx: Vec<Sha256dHash>,
	pub time: usize,
	pub mediantime: Option<usize>,
	pub nonce: u32,
	pub bits: String,
	#[serde(deserialize_with = "deserialize_difficulty")]
	pub difficulty: BigUint,
	pub chainwork: String,
	pub n_tx: usize,
	pub previousblockhash: Option<Sha256dHash>,
	pub nextblockhash: Option<Sha256dHash>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResult {
	pub hash: Sha256dHash,
	pub confirmations: usize,
	pub height: usize,
	pub version: u32,
	pub version_hex: Option<String>,
	pub merkleroot: Sha256dHash,
	pub time: usize,
	pub mediantime: Option<usize>,
	pub nonce: u32,
	pub bits: String,
	#[serde(deserialize_with = "deserialize_difficulty")]
	pub difficulty: BigUint,
	pub chainwork: String,
	pub n_tx: usize,
	pub previousblockhash: Option<Sha256dHash>,
	pub nextblockhash: Option<Sha256dHash>,
}

#[derive(Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetMiningInfoResult {
	pub blocks: u32,
	pub currentblockweight: u64,
	pub currentblocktx: usize,
	#[serde(deserialize_with = "deserialize_difficulty")]
	pub difficulty: BigUint,
	pub networkhashps: f64,
	pub pooledtx: usize,
	pub chain: String,
	pub warnings: String,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVinScriptSig {
	pub asm: String,
	pub hex: String,
}

impl GetRawTransactionResultVinScriptSig {
	pub fn script(&self) -> Result<Script, Error> {
		bitcoin_hex!(Script, &self.hex)
	}
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVin {
	pub txid: Sha256dHash,
	pub vout: u32,
	pub script_sig: GetRawTransactionResultVinScriptSig,
	pub sequence: u32,
	#[serde(default, deserialize_with = "deserialize_hex_array_opt")]
	pub txinwitness: Option<Vec<Vec<u8>>>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVoutScriptPubKey {
	pub asm: String,
	pub hex: String,
	pub req_sigs: usize,
	#[serde(rename = "type")]
	pub type_: String, //TODO(stevenroose) consider enum
	pub addresses: Vec<Address>,
}

impl GetRawTransactionResultVoutScriptPubKey {
	pub fn script(&self) -> Result<Script, Error> {
		bitcoin_hex!(Script, &self.hex)
	}
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVout {
	#[serde(deserialize_with = "deserialize_amount")]
	pub value: Amount,
	pub n: u32,
	pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResult {
	#[serde(rename = "in_active_chain")]
	pub in_active_chain: Option<bool>,
	pub hex: String,
	pub txid: Sha256dHash,
	pub hash: Sha256dHash,
	pub size: usize,
	pub vsize: usize,
	pub version: u32,
	pub locktime: u32,
	pub vin: Vec<GetRawTransactionResultVin>,
	pub vout: Vec<GetRawTransactionResultVout>,
	pub blockhash: Sha256dHash,
	pub confirmations: usize,
	pub time: usize,
	pub blocktime: usize,
}

impl GetRawTransactionResult {
	pub fn transaction(&self) -> Result<Transaction, Error> {
		bitcoin_hex!(Transaction, &self.hex)
	}
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetTxOutResult {
	pub bestblock: Sha256dHash,
	pub confirmations: usize,
	#[serde(deserialize_with = "deserialize_amount")]
	pub value: Amount,
	pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
	pub coinbase: bool,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentResult {
	pub txid: Sha256dHash,
	pub vout: u32,
	pub address: Address,
	pub script_pub_key: Script,
	#[serde(deserialize_with = "deserialize_amount")]
	pub amount: Amount,
	pub confirmations: usize,
	pub redeem_script: Option<Script>,
	pub spendable: bool,
	pub solvable: bool,
	pub safe: bool,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionResultError {
	pub txid: Sha256dHash,
	pub vout: u32,
	pub script_sig: Script,
	pub sequence: u32,
	pub error: String,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionResult {
	pub hex: String,
	pub complete: bool,
	#[serde(default)]
	pub errors: Vec<SignRawTransactionResultError>,
}

impl SignRawTransactionResult {
	pub fn transaction(&self) -> Result<Transaction, Error> {
		bitcoin_hex!(Transaction, &self.hex)
	}
}


// Custom types for input arguments.

// Used for signrawtransaction argument.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UTXO {
	pub txid: Sha256dHash,
	pub vout: u32,
	pub script_pub_key: Script,
	pub redeem_script: Script,
}


// Custom deserializer functions.

/// deserialize_amount deserializes a BTC-denominated floating point Bitcoin amount into the 
/// Amount type.
fn deserialize_amount<'de, D>(deserializer: D) -> Result<Amount, D::Error>
		where D: serde::Deserializer<'de> {
	Ok(Amount::from_btc(f64::deserialize(deserializer)?))
}

fn deserialize_difficulty<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
		where D: serde::Deserializer<'de> {
	let s = f64::deserialize(deserializer)?.to_string();
	let real = match s.split('.').nth(0) {
		Some(r) => r,
		None => return Err(D::Error::custom(&format!("error parsing difficulty: {}", s))),
	};
	BigUint::from_str(real)
		.map_err(|_| D::Error::custom(&format!("error parsing difficulty: {}", s)))
}

///// deserialize_hex deserializes a hex-encoded byte array.
//fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
//		where D: serde::Deserializer<'de> {
//	let h = String::deserialize(deserializer)?;
//	hex::decode(&h).map_err(|_| D::Error::custom(&format!("error parsing hex: {}", h)))
//}

/// deserialize_hex_array_opt deserializes a vector of hex-encoded byte arrays.
fn deserialize_hex_array_opt<'de, D>(deserializer: D) -> Result<Option<Vec<Vec<u8>>>, D::Error>
		where D: serde::Deserializer<'de> {
	//TODO(stevenroose) Revisit when issue is fixed:
	// https://github.com/serde-rs/serde/issues/723
	
	let v: Vec<String> = Vec::deserialize(deserializer)?;
	let mut res = Vec::new();
	for h in v.into_iter() {
		res.push(hex::decode(h).map_err(D::Error::custom)?);
	}
	Ok(Some(res))
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
	use super::*;
	use serde_json;

	macro_rules! deserializer {
		($j:expr) => {
			&mut serde_json::Deserializer::from_str($j)
		}
	}

	macro_rules! hash {
		($h:expr) => { Sha256dHash::from_hex($h).unwrap() };
	}

	macro_rules! addr {
		($a:expr) => { Address::from_str($a).unwrap() };
	}

	macro_rules! script {
		($s:expr) => { serde_json::from_str(&format!(r#""{}""#, $s)).unwrap() };
	}

	#[test]
	fn test_GetBlockResult() {
		let expected = GetBlockResult {
			hash: hash!("000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820"),
			confirmations: 1414401,
			size: 190,
			strippedsize: Some(190),
			weight: 760,
			height: 2,
			version: 1,
			version_hex: Some("00000001".into()),
			merkleroot: hash!("20222eb90f5895556926c112bb5aa0df4ab5abc3107e21a6950aec3b2e3541e2"),
			tx: vec![hash!("20222eb90f5895556926c112bb5aa0df4ab5abc3107e21a6950aec3b2e3541e2")],
			time: 1296688946,
			mediantime: Some(1296688928),
			nonce: 875942400,
			bits: "1d00ffff".into(),
			difficulty: 1u64.into(),
			chainwork: "0000000000000000000000000000000000000000000000000000000300030003".into(),
			n_tx: 1,
			previousblockhash: Some(hash!("00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206")),
			nextblockhash: Some(hash!("000000008b896e272758da5297bcd98fdc6d97c9b765ecec401e286dc1fdbe10")),
		};
		let json = r#"
			{
			  "hash": "000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820",
			  "confirmations": 1414401,
			  "strippedsize": 190,
			  "size": 190,
			  "weight": 760,
			  "height": 2,
			  "version": 1,
			  "versionHex": "00000001",
			  "merkleroot": "20222eb90f5895556926c112bb5aa0df4ab5abc3107e21a6950aec3b2e3541e2",
			  "tx": [
				"20222eb90f5895556926c112bb5aa0df4ab5abc3107e21a6950aec3b2e3541e2"
			  ],
			  "time": 1296688946,
			  "mediantime": 1296688928,
			  "nonce": 875942400,
			  "bits": "1d00ffff",
			  "difficulty": 1,
			  "chainwork": "0000000000000000000000000000000000000000000000000000000300030003",
			  "nTx": 1,
			  "previousblockhash": "00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206",
			  "nextblockhash": "000000008b896e272758da5297bcd98fdc6d97c9b765ecec401e286dc1fdbe10"
			}
		"#;
		assert_eq!(expected, serde_json::from_str(json).unwrap());
	}

	#[test]
	fn test_GetBlockHeaderResult() {
		let expected =  GetBlockHeaderResult {
			hash:  hash!("00000000000000039dc06adbd7666a8d1df9acf9d0329d73651b764167d63765"),
			confirmations: 29341,
			height: 1384958,
			version: 536870912,
			version_hex: Some("20000000".into()),
			merkleroot:  hash!("33d8a6f622182a4e844022bbc8aa51c63f6476708ad5cc5c451f2933753440d7"),
			time: 1534935138,
			mediantime: Some(1534932055),
			nonce: 871182973,
			bits: "1959273b".into(),
			difficulty: 48174374u64.into(),
			chainwork: "0000000000000000000000000000000000000000000000a3c78921878ecbafd4".into(),
			n_tx: 2647,
			previousblockhash: Some(hash!("000000000000002937dcaffd8367cfb05cd9ef2e3bd7a081de82696f70e719d9")),
			nextblockhash: Some(hash!("00000000000000331dddb553312687a4be62635ad950cde36ebc977c702d2791")),
		};
		let json = r#"
			{
			  "hash": "00000000000000039dc06adbd7666a8d1df9acf9d0329d73651b764167d63765",
			  "confirmations": 29341,
			  "height": 1384958,
			  "version": 536870912,
			  "versionHex": "20000000",
			  "merkleroot": "33d8a6f622182a4e844022bbc8aa51c63f6476708ad5cc5c451f2933753440d7",
			  "time": 1534935138,
			  "mediantime": 1534932055,
			  "nonce": 871182973,
			  "bits": "1959273b",
			  "difficulty": 48174374.44122773,
			  "chainwork": "0000000000000000000000000000000000000000000000a3c78921878ecbafd4",
			  "nTx": 2647,
			  "previousblockhash": "000000000000002937dcaffd8367cfb05cd9ef2e3bd7a081de82696f70e719d9",
			  "nextblockhash": "00000000000000331dddb553312687a4be62635ad950cde36ebc977c702d2791"
			}
		"#;
		assert_eq!(expected, serde_json::from_str(json).unwrap());
	}

	#[test]
	fn test_GetMiningInfoResult() {
		let expected = GetMiningInfoResult {
			blocks: 1415011,
			currentblockweight: 0,
			currentblocktx: 0,
			difficulty: 1u32.into(),
			networkhashps: 11970022568515.56,
			pooledtx: 110,
			chain: "test".into(),
			warnings:"Warning: unknown new rules activated (versionbit 28)".into(),
		};
		let json = r#"
			{
			  "blocks": 1415011,
			  "currentblockweight": 0,
			  "currentblocktx": 0,
			  "difficulty": 1,
			  "networkhashps": 11970022568515.56,
			  "pooledtx": 110,
			  "chain": "test",
			  "warnings": "Warning: unknown new rules activated (versionbit 28)"
			}
		"#;
		assert_eq!(expected, serde_json::from_str(json).unwrap());
	}

	#[test]
	fn test_GetRawTransactionResult() {
		let expected = GetRawTransactionResult {
			in_active_chain: None,
			hex: "0200000001586bd02815cf5faabfec986a4e50d25dbee089bd2758621e61c5fab06c334af0000000006b483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2dfeffffff021dc4260c010000001976a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac00e1f505000000001976a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88acfd211500".into(),
			txid: hash!("4a5b5266e1750488395ac15c0376c9d48abf45e4df620777fe8cff096f57aa91"),
			hash: hash!("4a5b5266e1750488395ac15c0376c9d48abf45e4df620777fe8cff096f57aa91"),
			size: 226,
			vsize: 226,
			version: 2,
			locktime: 1384957,
			vin: vec![GetRawTransactionResultVin{
				txid: hash!("f04a336cb0fac5611e625827bd89e0be5dd2504e6a98ecbfaa5fcf1528d06b58"),
				vout: 0,
				script_sig: GetRawTransactionResultVinScriptSig{
					asm: "3045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c[ALL] 03dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2d".into(),
					hex: "483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2d".into(),
				},
				sequence: 4294967294,
				txinwitness: None,

			}],
			vout: vec![GetRawTransactionResultVout{
				value: Amount::from_btc(44.98834461),
				n: 0,
				script_pub_key: GetRawTransactionResultVoutScriptPubKey{
					asm: "OP_DUP OP_HASH160 f602e88b2b5901d8aab15ebe4a97cf92ec6e03b3 OP_EQUALVERIFY OP_CHECKSIG".into(),
					hex: "76a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac".into(),
					req_sigs: 1,
					type_: "pubkeyhash".into(),
					addresses: vec![addr!("n3wk1KcFnVibGdqQa6jbwoR8gbVtRbYM4M")],
				},
			}, GetRawTransactionResultVout{
				value: Amount::from_btc(1.0),
				n: 1,
				script_pub_key: GetRawTransactionResultVoutScriptPubKey{
					asm: "OP_DUP OP_HASH160 687ffeffe8cf4e4c038da46a9b1d37db385a472d OP_EQUALVERIFY OP_CHECKSIG".into(),
					hex: "76a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88ac".into(),
					req_sigs: 1,
					type_: "pubkeyhash".into(),
					addresses: vec![addr!("mq3VuL2K63VKWkp8vvqRiJPre4h9awrHfA")],
				},
			}],
			blockhash: hash!("00000000000000039dc06adbd7666a8d1df9acf9d0329d73651b764167d63765"),
			confirmations: 29446,
			time: 1534935138,
			blocktime: 1534935138,
		};
		let json = r#"
			{
			  "txid": "4a5b5266e1750488395ac15c0376c9d48abf45e4df620777fe8cff096f57aa91",
			  "hash": "4a5b5266e1750488395ac15c0376c9d48abf45e4df620777fe8cff096f57aa91",
			  "version": 2,
			  "size": 226,
			  "vsize": 226,
			  "weight": 904,
			  "locktime": 1384957,
			  "vin": [
				{
				  "txid": "f04a336cb0fac5611e625827bd89e0be5dd2504e6a98ecbfaa5fcf1528d06b58",
				  "vout": 0,
				  "scriptSig": {
					"asm": "3045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c[ALL] 03dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2d",
					"hex": "483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2d"
				  },
				  "sequence": 4294967294
				}
			  ],
			  "vout": [
				{
				  "value": 44.98834461,
				  "n": 0,
				  "scriptPubKey": {
					"asm": "OP_DUP OP_HASH160 f602e88b2b5901d8aab15ebe4a97cf92ec6e03b3 OP_EQUALVERIFY OP_CHECKSIG",
					"hex": "76a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac",
					"reqSigs": 1,
					"type": "pubkeyhash",
					"addresses": [
					  "n3wk1KcFnVibGdqQa6jbwoR8gbVtRbYM4M"
					]
				  }
				},
				{
				  "value": 1.00000000,
				  "n": 1,
				  "scriptPubKey": {
					"asm": "OP_DUP OP_HASH160 687ffeffe8cf4e4c038da46a9b1d37db385a472d OP_EQUALVERIFY OP_CHECKSIG",
					"hex": "76a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88ac",
					"reqSigs": 1,
					"type": "pubkeyhash",
					"addresses": [
					  "mq3VuL2K63VKWkp8vvqRiJPre4h9awrHfA"
					]
				  }
				}
			  ],
			  "hex": "0200000001586bd02815cf5faabfec986a4e50d25dbee089bd2758621e61c5fab06c334af0000000006b483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2dfeffffff021dc4260c010000001976a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac00e1f505000000001976a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88acfd211500",
			  "blockhash": "00000000000000039dc06adbd7666a8d1df9acf9d0329d73651b764167d63765",
			  "confirmations": 29446,
			  "time": 1534935138,
			  "blocktime": 1534935138
			}
		"#;
		assert_eq!(expected, serde_json::from_str(json).unwrap());
		assert!(expected.transaction().is_ok());
		assert_eq!(expected.transaction().unwrap().input[0].previous_output.txid, 
				   "f04a336cb0fac5611e625827bd89e0be5dd2504e6a98ecbfaa5fcf1528d06b58".parse().unwrap());
		assert!(expected.vin[0].script_sig.script().is_ok());
		assert!(expected.vout[0].script_pub_key.script().is_ok());
	}

	#[test]
	fn test_GetTxOutResult() {
		let expected = GetTxOutResult {
			bestblock: hash!("000000000000002a1fde7234dc2bc016863f3d672af749497eb5c227421e44d5"),
			confirmations: 29505,
			value: Amount::from_btc(1.0),
			script_pub_key: GetRawTransactionResultVoutScriptPubKey{
				asm: "OP_DUP OP_HASH160 687ffeffe8cf4e4c038da46a9b1d37db385a472d OP_EQUALVERIFY OP_CHECKSIG".into(),
				hex: "76a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88ac".into(),
				req_sigs: 1,
				type_: "pubkeyhash".into(),
				addresses: vec![addr!("mq3VuL2K63VKWkp8vvqRiJPre4h9awrHfA")],
			},
			coinbase: false,
		};
		let json = r#"
			{
			  "bestblock": "000000000000002a1fde7234dc2bc016863f3d672af749497eb5c227421e44d5",
			  "confirmations": 29505,
			  "value": 1.00000000,
			  "scriptPubKey": {
				"asm": "OP_DUP OP_HASH160 687ffeffe8cf4e4c038da46a9b1d37db385a472d OP_EQUALVERIFY OP_CHECKSIG",
				"hex": "76a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88ac",
				"reqSigs": 1,
				"type": "pubkeyhash",
				"addresses": [
				  "mq3VuL2K63VKWkp8vvqRiJPre4h9awrHfA"
				]
			  },
			  "coinbase": false
			}
		"#;
		assert_eq!(expected, serde_json::from_str(json).unwrap());
		println!("{:?}", expected.script_pub_key.script());
		assert!(expected.script_pub_key.script().is_ok());
	}

	#[test]
	fn test_ListUnspentResult() {
		let expected = ListUnspentResult {
			txid: hash!("1e66743d6384496fe631501ba3f5b788d4bc193980b847f9e7d4e20d9202489f"),
			vout: 1,
			address: addr!("2N56rvr9bGj862UZMNQhv57nU4GXfMof1Xu"),
			script_pub_key: script!("a914820c9a334a89cb72bc4abfce96efc1fb202cdd9087"),
			amount: Amount::from_btc(2.0),
			confirmations: 29503,
			redeem_script: Some(script!("0014b1a84f7a5c60e58e2c6eee4b33e7585483399af0")),
			spendable: true,
			solvable: true,
			safe: true,
		};
		let json = r#"
			{
			  "txid": "1e66743d6384496fe631501ba3f5b788d4bc193980b847f9e7d4e20d9202489f",
			  "vout": 1,
			  "address": "2N56rvr9bGj862UZMNQhv57nU4GXfMof1Xu",
			  "label": "",
			  "redeemScript": "0014b1a84f7a5c60e58e2c6eee4b33e7585483399af0",
			  "scriptPubKey": "a914820c9a334a89cb72bc4abfce96efc1fb202cdd9087",
			  "amount": 2.00000000,
			  "confirmations": 29503,
			  "spendable": true,
			  "solvable": true,
			  "safe": true
			}
		"#;
		assert_eq!(expected, serde_json::from_str(json).unwrap());
	}

	//TODO(stevenroose) test SignRawTransactionResult
	
	//TODO(stevenroose) test UTXO

	#[test]
	fn test_deserialize_amount() {
		let vectors = vec![
			("0", Amount::from_sat(0)),
			("1", Amount::from_sat(100000000)),
			("1.00000001", Amount::from_sat(100000001)),
			("10000000.00000001", Amount::from_sat(1000000000000001)),
		];
		for vector in vectors.into_iter() {
			let d = deserialize_amount(deserializer!(vector.0)).unwrap();
			assert_eq!(d, vector.1);
		}
	}

	#[test]
	fn test_deserialize_difficulty() {
		let vectors = vec![
			("1.0", 1u64.into()),
			("0", 0u64.into()),
			("123.12345", 123u64.into()),
			("10000000.00000001", 10000000u64.into()),
		];
		for vector in vectors.into_iter() {
			let d = deserialize_difficulty(deserializer!(vector.0)).unwrap();
			assert_eq!(d, vector.1);
		}
	}

	//#[test]
	//fn test_deserialize_hex() {
	//	let vectors = vec![
	//		(r#""01020304a1ff""#, vec![1,2,3,4,161,255]),
	//		(r#""5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456""#, 
	//			Sha256dHash::from_data(&[]).as_bytes()[..].into()),
	//	];
	//	for vector in vectors.into_iter() {
	//		let d = deserialize_hex(deserializer!(vector.0)).unwrap();
	//		assert_eq!(d, vector.1);
	//	}
	//}

	#[test]
	fn test_deserialize_hex_array_opt() {
		let vectors = vec![
			(r#"["0102","a1ff"]"#, Some(vec![vec![1,2],vec![161,255]])),
		];
		for vector in vectors.into_iter() {
			let d = deserialize_hex_array_opt(deserializer!(vector.0)).unwrap();
			assert_eq!(d, vector.1);
		}
	}
}
