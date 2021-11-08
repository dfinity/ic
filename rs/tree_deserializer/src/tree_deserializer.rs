use ic_crypto_tree_hash::{
    Label,
    LabeledTree::{self, Leaf, SubTree},
};
use serde::{
    de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor},
    forward_to_deserialize_any,
};
use std::convert::TryInto;
use std::fmt;
use std::marker::PhantomData;

macro_rules! unsupported_type {
    ($func:ident, $msg:expr) => {
        fn $func<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            Err(Error::UnsupportedType($msg))
        }
    };
}

/// `Error` describes error conditions that can happen when deserializing a tree
/// into a data structure.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// The type with the given name is not supported by this deserializer.
    UnsupportedType(&'static str),
    /// One of the Deserializer method is not implemented (yet?).
    UnsupportedMethod(String),
    /// The expected size of the tuple being parsed doesn't match the data.
    BadTupleSize { expected: usize, actual: usize },
    /// Failed to parse a string from a blob.
    BadString(String),
    /// The tree structure is incompatible with the data being parsed.
    BadState(String),
    /// Cannot decode a label into the requested data type.
    BadLabel(String),
    /// Custom error produced by serde.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedType(t) => write!(f, "unsupported type: {}", t),
            Self::UnsupportedMethod(m) => write!(f, "method {} is not implemented", m),
            Self::BadTupleSize { expected, actual } => write!(
                f,
                "cannot decode sequence of {} elements into a tuple of size {}",
                actual, expected
            ),
            Self::BadLabel(s) => write!(f, "failed to deserialize label: {}", s),
            Self::BadString(s) => write!(f, "failed to convert byte sequence to a string: {}", s),
            Self::BadState(s) => write!(
                f,
                "tree shape is incompatible with the data structure: {}",
                s
            ),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for Error {}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(t: T) -> Self {
        Self::Other(t.to_string())
    }
}

/// `LabeledTreeDeserializer` is a deserializer that decodes a labeled tree into
/// a data structure implementing serde::Deserialize.
///
/// This deserializer only supports a limited subset of serde data types:
///
/// 1. u32 and u64 (decoded as Big-Endian).
/// 2. Bytes and byte buffers.
/// 3. Strings, identifiers and string slices.
/// 4. Maps and sequences (when decoding subtree as a sequence, edge labels will
///    be discarded).
/// 5. Structs.
///
/// Other integer types and enums are not supported (it is definitely possible
/// to add more types in future, but there is no need for now).
///
/// NOTE: this deserializer supports borrowed data, so a data structure can
/// reference the tree leaves directly.  This is especially useful if the leaves
/// contain big blobs (e.g., encoded messages).
#[derive(Clone)]
pub struct LabeledTreeDeserializer<'a> {
    root: &'a LabeledTree<Vec<u8>>,
}

impl<'a> LabeledTreeDeserializer<'a> {
    pub fn new(root: &'a LabeledTree<Vec<u8>>) -> Self {
        Self { root }
    }
}

/// An adapter to deserialize maps.
struct TreeMapAccess<'a> {
    value: Option<&'a LabeledTree<Vec<u8>>>,
    key_iter: std::slice::Iter<'a, Label>,
    val_iter: std::slice::Iter<'a, LabeledTree<Vec<u8>>>,
}

impl<'de> MapAccess<'de> for TreeMapAccess<'de> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        match self.key_iter.next() {
            Some(label) => {
                let tree = self.val_iter.next().unwrap();
                self.value = Some(tree);
                let d = LabelDeserializer(label.as_bytes());
                seed.deserialize(d).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let t = self.value.ok_or_else(|| {
            Error::BadState("attempt to take a value before getting the key".to_string())
        })?;
        let d = LabeledTreeDeserializer::new(t);
        seed.deserialize(d)
    }
}

/// An adapter to deserialize trees as sequences.
struct TreeSeqAccess<'de>(std::slice::Iter<'de, LabeledTree<Vec<u8>>>);

impl<'de> SeqAccess<'de> for TreeSeqAccess<'de> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        match self.0.next() {
            Some(t) => seed.deserialize(LabeledTreeDeserializer::new(t)).map(Some),
            None => Ok(None),
        }
    }
}

/// An adapter to deserialize leaves as byte sequences.
struct ByteSeqAccess<'de>(std::slice::Iter<'de, u8>);

impl<'de> SeqAccess<'de> for ByteSeqAccess<'de> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        match self.0.next() {
            Some(b) => seed.deserialize(ByteSerializer(*b, PhantomData)).map(Some),
            None => Ok(None),
        }
    }
}

impl<'de> Deserializer<'de> for LabeledTreeDeserializer<'de> {
    type Error = Error;

    fn is_human_readable(&self) -> bool {
        false
    }

    unsupported_type!(deserialize_unit, "unit");
    unsupported_type!(deserialize_bool, "bool");
    unsupported_type!(deserialize_char, "char");
    unsupported_type!(deserialize_i8, "i8");
    unsupported_type!(deserialize_i16, "i16");
    unsupported_type!(deserialize_i32, "i32");
    unsupported_type!(deserialize_i64, "i64");
    unsupported_type!(deserialize_u8, "u8");
    unsupported_type!(deserialize_u16, "u16");
    unsupported_type!(deserialize_f32, "f32");
    unsupported_type!(deserialize_f64, "f64");

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.root {
            Leaf(b) => visitor.visit_borrowed_bytes(&b[..]),
            SubTree(children) => visitor.visit_map(TreeMapAccess {
                key_iter: children.keys().iter(),
                val_iter: children.values().iter(),
                value: None,
            }),
        }
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.root {
            Leaf(b) => {
                if b.len() == 4 {
                    visitor.visit_u32(u32::from_be_bytes(b[..].try_into().unwrap()))
                } else {
                    Err(Error::BadState(format!(
                        "cannot decode u32 from a byte array with {} bytes",
                        b.len()
                    )))
                }
            }
            SubTree(_) => Err(Error::BadState(
                "cannot decode u32 from a subtree".to_string(),
            )),
        }
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.root {
            Leaf(b) => {
                if b.len() == 8 {
                    visitor.visit_u64(u64::from_be_bytes(b[..].try_into().unwrap()))
                } else {
                    Err(Error::BadState(format!(
                        "cannot decode u64 from a byte array with {} bytes",
                        b.len()
                    )))
                }
            }
            SubTree(_) => Err(Error::BadState(
                "cannot decode u64 from a subtree".to_string(),
            )),
        }
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_string(visitor)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.root {
            Leaf(b) => match String::from_utf8(b.clone()) {
                Ok(s) => visitor.visit_string(s),
                Err(err) => Err(Error::BadString(format!(
                    "failed to decode a string from a byte array: {}",
                    err
                ))),
            },
            SubTree(_) => Err(Error::BadState(
                "cannot deserialize a string from a subtree".to_string(),
            )),
        }
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.root {
            Leaf(b) => visitor.visit_borrowed_bytes(b),
            SubTree(_) => Err(Error::BadState(
                "cannot deserialize bytes from a subtree".to_string(),
            )),
        }
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.root {
            Leaf(_) => visitor.visit_some(self),
            SubTree(t) => {
                if t.is_empty() {
                    visitor.visit_none()
                } else {
                    visitor.visit_some(self)
                }
            }
        }
    }
    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.root {
            Leaf(b) => visitor.visit_seq(ByteSeqAccess(b[..].iter())),
            SubTree(children) => visitor.visit_seq(TreeSeqAccess(children.values().iter())),
        }
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.root {
            Leaf(bytes) => {
                if bytes.len() != len {
                    return Err(Error::BadTupleSize {
                        expected: len,
                        actual: bytes.len(),
                    });
                }
                self.deserialize_seq(visitor)
            }
            SubTree(children) => {
                if children.len() != len {
                    return Err(Error::BadTupleSize {
                        expected: len,
                        actual: children.len(),
                    });
                }
                self.deserialize_seq(visitor)
            }
        }
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.root {
            Leaf(_) => Err(Error::BadState(
                "cannot decode a map from a leaf".to_string(),
            )),
            SubTree(children) => visitor.visit_map(TreeMapAccess {
                key_iter: children.keys().iter(),
                val_iter: children.values().iter(),
                value: None,
            }),
        }
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(Error::UnsupportedType("enum"))
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_string(visitor)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_any(visitor)
    }
}

/// A deserializer for labels.
struct LabelDeserializer<'a>(&'a [u8]);

impl<'de> Deserializer<'de> for LabelDeserializer<'de> {
    type Error = Error;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if self.0.len() == 4 {
            visitor.visit_u32(u32::from_be_bytes(self.0[..].try_into().unwrap()))
        } else {
            Err(Error::BadLabel(format!(
                "cannot decode u32 from a label with {} bytes",
                self.0.len()
            )))
        }
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if self.0.len() == 8 {
            visitor.visit_u64(u64::from_be_bytes(self.0[..].try_into().unwrap()))
        } else {
            Err(Error::BadLabel(format!(
                "cannot to decode u64 from a label with {} bytes",
                self.0.len()
            )))
        }
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_string(visitor)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match String::from_utf8(self.0.to_vec()) {
            Ok(s) => visitor.visit_string(s),
            Err(err) => Err(Error::BadLabel(format!(
                "failed to decode a string from a byte array: {}",
                err
            ))),
        }
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_string(visitor)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_borrowed_bytes(self.0)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(ByteSeqAccess(self.0.iter()))
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u128 f32 f64 char
            option unit unit_struct tuple
            tuple_struct map struct enum ignored_any
    }
}

/// A serializer that populates a single byte.
/// Only needed for decoding Vec<u8> as sequences.
struct ByteSerializer<'de>(u8, PhantomData<&'de u8>);

impl<'de> Deserializer<'de> for ByteSerializer<'de> {
    type Error = Error;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(self.0)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(self.0)
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u16 u32 u64 u128 f32 f64 char
            option unit unit_struct newtype_struct seq tuple
            bytes byte_buf str string
            tuple_struct map struct enum identifier ignored_any
    }
}
