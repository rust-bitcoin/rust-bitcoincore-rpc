//! Some types that are used are parameters to function calls.

// DEVELOPER NOTES
//
// There are quite some subtleties here in this module.
// * It's best to always look around closely to other implementations and
//   do as they do.
//
// * The `impl<T> X for &T` impls are for params that are used in slices,
//   so that you can both do `&[&my_tx]` but also `&my_txs`.
// * Params that include `str`, must have `+ ?Sized` in these &T trait impls.

use std::fmt;

use crate::bitcoin::hashes::sha256d;
use crate::bitcoin::{self, Address, Block, Transaction};
use crate::bitcoin::psbt::PartiallySignedTransaction;
use crate::bitcoin::sighash::EcdsaSighashType;

/// Outputs hex into an object implementing `fmt::Write`.
///
/// This is usually more efficient than going through a `String` using [`ToHex`].
// NB taken from bitcoin_hashes::hex
fn format_hex(data: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    let prec = f.precision().unwrap_or(2 * data.len());
    let width = f.width().unwrap_or(2 * data.len());
    for _ in (2 * data.len())..width {
        f.write_str("0")?;
    }
    for ch in data.iter().take(prec / 2) {
        write!(f, "{:02x}", *ch)?;
    }
    if prec < 2 * data.len() && prec % 2 == 1 {
        write!(f, "{:x}", data[prec / 2] / 16)?;
    }
    Ok(())
}

/// Marker trait for arguments that identify a block by
/// either its hash or block height.
///
/// In the RPC documentation these are generally named hash_or_height.
pub trait BlockRef: serde::Serialize + Sync {}

impl BlockRef for bitcoin::BlockHash {}
impl BlockRef for sha256d::Hash {}
impl BlockRef for String {}
impl<'a> BlockRef for &'a String {}
impl<'a> BlockRef for &'a str {}
impl BlockRef for usize {}
impl BlockRef for u64 {}
impl BlockRef for u32 {}
impl BlockRef for u16 {}
impl BlockRef for u8 {}
impl BlockRef for isize {}
impl BlockRef for i64 {}
impl BlockRef for i32 {}
impl BlockRef for i16 {}
impl BlockRef for i8 {}

/// Trait for parameter types that are serializable as a string.
pub trait StringParam {
    fn write_string(&self, f: &mut fmt::Formatter) -> fmt::Result;
}

impl StringParam for str {
    fn write_string(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl StringParam for String {
    fn write_string(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<T: StringParam + ?Sized> StringParam for &T {
    fn write_string(&self, f: &mut fmt::Formatter) -> fmt::Result {
        StringParam::write_string(*self, f)
    }
}

/// General trait for any object that can be accepted as an argument
/// that should be serialized as hex.
pub trait HexParam {
    fn write_hex(&self, f: &mut fmt::Formatter) -> fmt::Result;
}

impl HexParam for str {
    fn write_hex(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl HexParam for String {
    fn write_hex(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl HexParam for [u8] {
    fn write_hex(&self, f: &mut fmt::Formatter) -> fmt::Result {
        format_hex(self, f)
    }
}

impl HexParam for Vec<u8> {
    fn write_hex(&self, f: &mut fmt::Formatter) -> fmt::Result {
        format_hex(self, f)
    }
}

impl HexParam for Transaction {
    fn write_hex(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = bitcoin::consensus::encode::serialize(self);
        HexParam::write_hex(&bytes[..], f)
    }
}

impl HexParam for Block {
    fn write_hex(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = bitcoin::consensus::encode::serialize(self);
        HexParam::write_hex(&bytes[..], f)
    }
}

impl<T: HexParam + ?Sized> HexParam for &T {
    fn write_hex(&self, f: &mut fmt::Formatter) -> fmt::Result {
        HexParam::write_hex(*self, f)
    }
}

/// A marker trait for parameters that represent transactions.
pub trait TxParam: HexParam + Sync {}

impl TxParam for str {}
impl TxParam for String {}
impl TxParam for [u8] {}
impl TxParam for Vec<u8> {}
impl TxParam for Transaction {}
impl <T: TxParam + ?Sized> TxParam for &T {}

/// A marker trait for parameters that represent blocks.
pub trait BlockParam: HexParam + Sync {}

impl BlockParam for str {}
impl BlockParam for String {}
impl BlockParam for [u8] {}
impl BlockParam for Vec<u8> {}
impl BlockParam for Block {}

/// A marker trait for parameters that represent Bitcoin addresses.
pub trait AddressParam: StringParam + Sync {}

impl StringParam for Address {
    fn write_string(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
impl StringParam for Address<bitcoin::address::NetworkUnchecked> {
    fn write_string(&self, f: &mut fmt::Formatter) -> fmt::Result {
        //TODO(stevenroose) await landing of fmt for all addresses
        write!(f, "{}", self.clone().assume_checked())
    }
}

impl AddressParam for Address {}
impl AddressParam for Address<bitcoin::address::NetworkUnchecked> {}
impl AddressParam for str {}
impl AddressParam for String {}
impl <T: AddressParam + ?Sized> AddressParam for &T {}

/// A marker trait for parameters that represent sighash flags.
pub trait SighashParam: StringParam + Sync {}

impl StringParam for EcdsaSighashType {
    fn write_string(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            EcdsaSighashType::All => "ALL",
            EcdsaSighashType::None => "NONE",
            EcdsaSighashType::Single => "SINGLE",
            EcdsaSighashType::AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
            EcdsaSighashType::NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
            EcdsaSighashType::SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
        })
    }
}
impl SighashParam for EcdsaSighashType {}
impl <T: SighashParam> SighashParam for &T {}

/// A marker trait for parameters that represent partially signed Bitcoin transactions.
pub trait PsbtParam: StringParam + Sync {}

impl StringParam for PartiallySignedTransaction {
    fn write_string(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // ideally we won't rely on fmt::Display for this, but have an explicit base64 getter
        fmt::Display::fmt(self, f)
    }
}

impl PsbtParam for PartiallySignedTransaction {}
impl PsbtParam for str {}
impl PsbtParam for String {}
impl <T: PsbtParam + ?Sized> PsbtParam for &T {}

#[cfg(test)]
mod test {
    use super::*;

    use std::str::FromStr;

    use async_trait::async_trait;
    use bitcoin::BlockHash;
    use bitcoin::hash_types::TxMerkleNode;
    use bitcoin::hashes::Hash;
    use bitcoin::blockdata::locktime::absolute::LockTime;
    use jsonrpc::Request;

    use crate::{AsyncClient, Error, Result, SyncClient};

    struct SyncDummy;

    #[async_trait(?Send)]
    impl SyncClient for SyncDummy {
        fn handle_request<'r, T>(&self, _: Request<'r, T>) -> Result<T> {
            Err(Error::ReturnedError("dummy".into()))
        }

        fn version(&self) -> Result<usize> { Ok(0) }
        fn refresh_version(&self) -> Result<()> { Ok(()) }
    }

    struct AsyncDummy;

    #[async_trait(?Send)]
    impl AsyncClient for AsyncDummy {
        async fn handle_request<'r, T>(&self, _: Request<'r, T>) -> Result<T> {
            Err(Error::ReturnedError("dummy".into()))
        }

        async fn version(&self) -> Result<usize> { Ok(0) }
        async fn refresh_version(&self) -> Result<()> { Ok(()) }
    }

    fn new_tx() -> Transaction {
        Transaction {
            version: 0,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    }

    fn new_psbt() -> PartiallySignedTransaction {
        PartiallySignedTransaction {
            unsigned_tx: new_tx(),
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![],
            outputs: vec![],
        }
    }

    fn new_block() -> Block {
        Block {
            header: bitcoin::block::Header {
                version: Default::default(),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: Default::default(),
                nonce: 0,
            },
            txdata: vec![],
        }
    }
    
    // What follows are some tests that simply check if the compiler allows
    // all the different method argument passings that we intend.
    // These tests only test a single method for each case, so they rely on
    // all similar methods in the APIs to have similar semantics.
    // We test both sync and async because async often has more subtle
    // semantics.

    #[test]
    fn test_tx_param_sync() {
        let c = SyncDummy;

        let bytes = vec![1u8, 2];
        let string = "deadbeef".to_owned();
        let strr = "deadbeef";
        let tx = new_tx();
        let txs = vec![ new_tx(), new_tx() ];

        let _ = c.decode_raw_transaction("deadbeef", None);
        let _ = c.decode_raw_transaction(strr, None);
        let _ = c.decode_raw_transaction(&string, None);
        let _ = c.decode_raw_transaction(&bytes, None);
        let _ = c.decode_raw_transaction(&bytes[..], None);
        let _ = c.decode_raw_transaction(&tx, None);
        // slice
        let _ = c.test_mempool_accept(&["deadbeef"], None);
        let _ = c.test_mempool_accept(&[&string], None);
        let _ = c.test_mempool_accept(&[string], None);
        let _ = c.test_mempool_accept(&[&bytes], None);
        let _ = c.test_mempool_accept(&[&bytes[..]], None);
        let _ = c.test_mempool_accept(&[bytes], None);
        let _ = c.test_mempool_accept(&[&tx], None);
        let _ = c.test_mempool_accept(&[tx], None);
        let _ = c.test_mempool_accept(&txs, None);
        let _ = c.test_mempool_accept(&txs[..], None);
    }

    #[test]
    fn test_tx_param_async() {
        let c = AsyncDummy;

        let bytes = vec![1u8, 2];
        let string = "deadbeef".to_owned();
        let strr = "deadbeef";
        let tx = new_tx();
        let txs = vec![ new_tx(), new_tx() ];

        let _ = c.decode_raw_transaction("deadbeef", None);
        let _ = c.decode_raw_transaction(strr, None);
        let _ = c.decode_raw_transaction(&string, None);
        let _ = c.decode_raw_transaction(&bytes, None);
        let _ = c.decode_raw_transaction(&bytes[..], None);
        let _ = c.decode_raw_transaction(&tx, None);
        // slice
        let _ = c.test_mempool_accept(&["deadbeef"], None);
        let _ = c.test_mempool_accept(&[&string], None);
        let _ = c.test_mempool_accept(&[string], None);
        let _ = c.test_mempool_accept(&[&bytes], None);
        let _ = c.test_mempool_accept(&[&bytes[..]], None);
        let _ = c.test_mempool_accept(&[bytes], None);
        let _ = c.test_mempool_accept(&[&tx], None);
        let _ = c.test_mempool_accept(&[tx], None);
        let _ = c.test_mempool_accept(&txs, None);
        let _ = c.test_mempool_accept(&txs[..], None);
    }

    #[test]
    fn test_block_param_sync() {
        let c = SyncDummy;

        let bytes = vec![1u8, 2];
        let string = "deadbeef".to_owned();
        let strr = "deadbeef";
        let block = new_block();

        let _ = c.submit_block("deadbeef");
        let _ = c.submit_block(strr);
        let _ = c.submit_block(&string);
        let _ = c.submit_block(&bytes);
        let _ = c.submit_block(&bytes[..]);
        let _ = c.submit_block(&block);
    }

    #[test]
    fn test_block_param_async() {
        let c = AsyncDummy;

        let bytes = vec![1u8, 2];
        let string = "deadbeef".to_owned();
        let strr = "deadbeef";
        let block = new_block();

        let _ = c.submit_block("deadbeef");
        let _ = c.submit_block(strr);
        let _ = c.submit_block(&string);
        let _ = c.submit_block(&bytes);
        let _ = c.submit_block(&bytes[..]);
        let _ = c.submit_block(&block);
    }

    #[test]
    fn test_address_param_sync() {
        let c = SyncDummy;

        let string = "deadbeef".to_owned();
        let strr = "deadbeef";
        let addr = Address::from_str("1HYjUtfC5KGrB1QrDzbWXjam5dw1VofKf2").unwrap().assume_checked();
        let addr_uc = Address::from_str("1HYjUtfC5KGrB1QrDzbWXjam5dw1VofKf2").unwrap();
        let addrs = vec![addr.clone(), addr.clone()];

        let _ = c.get_address_info("deadbeef");
        let _ = c.get_address_info(strr);
        let _ = c.get_address_info(&string);
        let _ = c.get_address_info(&addr);
        let _ = c.get_address_info(&addr_uc);
        // slice
        let _ = c.list_unspent(None, None, Some(&["deadbeef"]), None, None);
        let _ = c.list_unspent(None, None, Some(&[&string]), None, None);
        let _ = c.list_unspent(None, None, Some(&[string]), None, None);
        let _ = c.list_unspent(None, None, Some(&[&addr]), None, None);
        let _ = c.list_unspent(None, None, Some(&[addr]), None, None);
        let _ = c.list_unspent(None, None, Some(&addrs), None, None);
        let _ = c.list_unspent(None, None, Some(&addrs[..]), None, None);
    }

    #[test]
    fn test_address_param_async() {
        let c = AsyncDummy;

        let string = "deadbeef".to_owned();
        let strr = "deadbeef";
        let addr = Address::from_str("1HYjUtfC5KGrB1QrDzbWXjam5dw1VofKf2").unwrap().assume_checked();
        let addr_uc = Address::from_str("1HYjUtfC5KGrB1QrDzbWXjam5dw1VofKf2").unwrap();
        let addrs = vec![addr.clone(), addr.clone()];

        let _ = c.get_address_info("deadbeef");
        let _ = c.get_address_info(strr);
        let _ = c.get_address_info(&string);
        let _ = c.get_address_info(&addr);
        let _ = c.get_address_info(&addr_uc);
        // slice
        let _ = c.list_unspent(None, None, Some(&["deadbeef"]), None, None);
        let _ = c.list_unspent(None, None, Some(&[&string]), None, None);
        let _ = c.list_unspent(None, None, Some(&[string]), None, None);
        let _ = c.list_unspent(None, None, Some(&[&addr]), None, None);
        let _ = c.list_unspent(None, None, Some(&[addr]), None, None);
        let _ = c.list_unspent(None, None, Some(&addrs), None, None);
        let _ = c.list_unspent(None, None, Some(&addrs[..]), None, None);
    }

    #[test]
    fn test_psbt_param_sync() {
        let c = SyncDummy;

        let string = "deadbeef".to_owned();
        let strr = "deadbeef";
        let psbt = new_psbt();
        let psbts = vec![ new_psbt(), new_psbt() ];

        let _ = c.finalize_psbt("deadbeef", None);
        let _ = c.finalize_psbt(strr, None);
        let _ = c.finalize_psbt(&string, None);
        let _ = c.finalize_psbt(&psbt, None);
        // slice
        let _ = c.join_psbts(&["deadbeef"]);
        let _ = c.join_psbts(&[&string]);
        let _ = c.join_psbts(&[string]);
        let _ = c.join_psbts(&[&psbt]);
        let _ = c.join_psbts(&[psbt]);
        let _ = c.join_psbts(&psbts);
        let _ = c.join_psbts(&psbts[..]);
    }

    #[test]
    fn test_psbt_param_async() {
        let c = AsyncDummy;

        let string = "deadbeef".to_owned();
        let strr = "deadbeef";
        let psbt = new_psbt();
        let psbts = vec![ new_psbt(), new_psbt() ];

        let _ = c.finalize_psbt("deadbeef", None);
        let _ = c.finalize_psbt(strr, None);
        let _ = c.finalize_psbt(&string, None);
        let _ = c.finalize_psbt(&psbt, None);
        // slice
        let _ = c.join_psbts(&["deadbeef"]);
        let _ = c.join_psbts(&[&string]);
        let _ = c.join_psbts(&[string]);
        let _ = c.join_psbts(&[&psbt]);
        let _ = c.join_psbts(&[psbt]);
        let _ = c.join_psbts(&psbts);
        let _ = c.join_psbts(&psbts[..]);
    }
}
