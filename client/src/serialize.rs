
use std::cell::RefCell;
use std::fmt;

use serde::ser::{Serialize, Serializer, SerializeSeq};

use crate::json::bitcoin::{OutPoint, Txid};
use crate::{HexParam, StringParam};

/// Wrapper for types with a custom string-based serialization.
pub struct StringSerializeWrapper<'a, T: ?Sized>(pub &'a T);

impl<'a, T: StringParam + ?Sized> serde::Serialize for StringSerializeWrapper<'a, T> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        struct Fmt<'a, T: ?Sized>(&'a T);
        impl<'a, T: StringParam + ?Sized> fmt::Display for Fmt<'a, T> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                StringParam::write_string(self.0, f)
            }
        }

        s.collect_str(&Fmt(self.0))
    }
}

/// A wrapper for an argument to be serialized as a list of strings.
pub struct StringListSerializeWrapper<'a, T>(pub &'a [T]);

impl<'a, T: StringParam> Serialize for StringListSerializeWrapper<'a, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        for e in self.0.iter() {
            SerializeSeq::serialize_element(&mut seq, &StringSerializeWrapper(e))?;
        }
        SerializeSeq::end(seq)
    }
}

/// A wrapper for an argument to be serialized as hex.
pub struct HexSerializeWrapper<'a, T: ?Sized>(pub &'a T);

impl<'a, T: HexParam + ?Sized> Serialize for HexSerializeWrapper<'a, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        struct Fmt<'a, T: ?Sized>(&'a T);
        impl<'a, T: HexParam + ?Sized> fmt::Display for Fmt<'a, T> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                HexParam::write_hex(self.0, f)
            }
        }

        serializer.collect_str(&Fmt(self.0))
    }
}

/// A wrapper for an argument to be serialized as a list of hex objects.
pub struct HexListSerializeWrapper<'a, T>(pub &'a [T]);

impl<'a, T: HexParam> Serialize for HexListSerializeWrapper<'a, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        for e in self.0.iter() {
            SerializeSeq::serialize_element(&mut seq, &HexSerializeWrapper(e))?;
        }
        SerializeSeq::end(seq)
    }
}

/// A wrapper type to serialize a series of objects as a JSON list.
/// Implemented for Iterators over serializable objects.
pub(crate) struct ListSerializeWrapper<T>(RefCell<Option<T>>);

impl<T> From<T> for ListSerializeWrapper<T> {
    fn from(v: T) -> ListSerializeWrapper<T> {
        ListSerializeWrapper(RefCell::new(Some(v)))
    }
}

impl<E, I> serde::Serialize for ListSerializeWrapper<I>
where
    E: serde::Serialize,
    I: IntoIterator<Item = E>,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        for e in self.0.borrow_mut().take().unwrap().into_iter() {
            serde::ser::SerializeSeq::serialize_element(&mut seq, &e)?;
        }
        serde::ser::SerializeSeq::end(seq)
    }
}

/// A wrapper type to serialize something as a JSON map.
/// Implemented for Iterators over key-value pairs.
pub struct MapSerializeWrapper<T>(RefCell<T>);

impl<T> From<T> for MapSerializeWrapper<T> {
    fn from(v: T) -> MapSerializeWrapper<T> {
        MapSerializeWrapper(RefCell::new(v))
    }
}

impl<K, V, I> serde::Serialize for MapSerializeWrapper<I>
where
    K: serde::Serialize,
    V: serde::Serialize,
    I: Iterator<Item = (K, V)>,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (k, v) in &mut *self.0.borrow_mut() {
            serde::ser::SerializeMap::serialize_entry(&mut map, &k, &v)?;
        }
        serde::ser::SerializeMap::end(map)
    }
}

/// A wrapper type to serialize OutPoint as JSON objects.
pub struct OutPointListObjectSerializeWrapper<'a>(pub &'a [OutPoint]);

impl<'a> serde::Serialize for OutPointListObjectSerializeWrapper<'a> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(serde::Serialize)]
        struct JsonOutPoint {
            pub txid: Txid,
            pub vout: u32,
        }

        impl From<OutPoint> for JsonOutPoint {
            fn from(o: OutPoint) -> JsonOutPoint {
                JsonOutPoint {
                    txid: o.txid,
                    vout: o.vout,
                }
            }
        }

        let mut seq = serializer.serialize_seq(None)?;
        for e in self.0.iter() {
            SerializeSeq::serialize_element(&mut seq, &JsonOutPoint::from(*e))?;
        }
        SerializeSeq::end(seq)
    }
}
