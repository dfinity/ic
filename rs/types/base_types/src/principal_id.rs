use crate::pb_internal::v1::PrincipalId as PrincipalIdProto;
use candid::types::{Type, TypeId};
use ic_crypto_sha256::Sha224;
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};

/// The type representing principals as described in the [interface
/// spec](https://sdk.dfinity.org/docs/interface-spec/index.html#_principals).
///
/// A principal is just a blob that is displayed in a particular way.
/// (see https://sdk.dfinity.org/docs/interface-spec/index.html#textual-ids)
///
/// Principals have variable length, bounded by 29 bytes. Since we
/// want [`PrincipalId`] to implement the Copy trait, we encode them as
/// a fixed-size array and a length.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PrincipalId {
    len: usize,
    data: [u8; Self::MAX_LENGTH_IN_BYTES],
}

impl PrincipalId {
    pub const MAX_LENGTH_IN_BYTES: usize = 29;
    const HASH_LEN_IN_BYTES: usize = 28;
    const CRC_LENGTH_IN_BYTES: usize = 4;

    pub fn as_slice(&self) -> &[u8] {
        // The principal is stored as part of the array, starting from position 0
        // and taking up "len" bytes. We thus need to truncate the array.
        &self.data[..self.len]
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.to_vec()
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let blob = self.as_slice();
        // Calculate checksum...
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&blob);
        let checksum = hasher.finalize();

        // ...combine blobs...
        let mut bytes = vec![];
        bytes.extend_from_slice(&(checksum.to_be_bytes()));
        bytes.extend_from_slice(&blob);

        // ...encode in base32...
        let mut s = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &bytes);
        s.make_ascii_lowercase();

        // ...write out the string with dashes.
        while s.len() > 5 {
            let rest = s.split_off(5);
            write!(f, "{}-", s)?;
            s = rest;
        }
        write!(f, "{}", s)
    }
}

impl fmt::Debug for PrincipalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

/// Represents an error that can occur when parsing a blob into a
/// [`PrincipalId`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrincipalIdBlobParseError {
    TooLong(usize),
}

impl fmt::Display for PrincipalIdBlobParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong(n) => write!(
                f,
                "Principal id must contain at most {} bytes, got {}",
                PrincipalId::MAX_LENGTH_IN_BYTES,
                n
            ),
        }
    }
}

impl std::error::Error for PrincipalIdBlobParseError {}

impl Into<Vec<u8>> for PrincipalId {
    fn into(self) -> Vec<u8> {
        self.to_vec()
    }
}

/// The [`TryFrom`] trait should only be used when parsing data; fresh ids
/// should always be created with the functions below (PrincipalId::new_*)
impl TryFrom<&[u8]> for PrincipalId {
    type Error = PrincipalIdBlobParseError;

    fn try_from(blob: &[u8]) -> Result<Self, Self::Error> {
        if blob.len() > Self::MAX_LENGTH_IN_BYTES {
            return Err(PrincipalIdBlobParseError::TooLong(blob.len()));
        }

        let mut id = PrincipalId {
            len: blob.len(),
            data: [0; Self::MAX_LENGTH_IN_BYTES],
        };
        id.data[..blob.len()].copy_from_slice(&blob[..]);
        Ok(id)
    }
}

impl TryFrom<Vec<u8>> for PrincipalId {
    type Error = PrincipalIdBlobParseError;
    fn try_from(blob: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(blob.as_slice())
    }
}
impl TryFrom<&Vec<u8>> for PrincipalId {
    type Error = PrincipalIdBlobParseError;
    fn try_from(blob: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(blob.as_slice())
    }
}

impl AsRef<[u8]> for PrincipalId {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Represents an error that can occur when parsing a string into a
/// [`PrincipalId`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrincipalIdParseError {
    TooLong,
    TooShort,
    NotBase32,
    Wrong { expected: String },
}

impl std::error::Error for PrincipalIdParseError {}

impl fmt::Display for PrincipalIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "principal textual representation is too long"),
            Self::TooShort => write!(f, "principal textual representation is too short"),
            Self::NotBase32 => write!(
                f,
                "cannot decode principal textual representation as base32"
            ),
            Self::Wrong { expected } => write!(
                f,
                "principal textual not in normal form, expected {}",
                expected
            ),
        }
    }
}

impl std::str::FromStr for PrincipalId {
    type Err = PrincipalIdParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // Strategy: Parse very liberally, then pretty-print and compare output.
        // This is both simpler and yields better error messages.

        let mut s = input.to_string();
        s.make_ascii_lowercase();
        s.retain(|c| c.is_ascii_alphanumeric());
        match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &s) {
            Some(mut bytes) => {
                if bytes.len() < Self::CRC_LENGTH_IN_BYTES {
                    return Err(PrincipalIdParseError::TooShort);
                }
                if bytes.len() > Self::MAX_LENGTH_IN_BYTES + Self::CRC_LENGTH_IN_BYTES {
                    return Err(PrincipalIdParseError::TooLong);
                }
                let result =
                    PrincipalId::try_from(&bytes.split_off(Self::CRC_LENGTH_IN_BYTES)[..]).unwrap();
                let expected = format!("{}", result);
                if input != expected {
                    return Err(PrincipalIdParseError::Wrong { expected });
                }
                Ok(result)
            }
            None => Err(PrincipalIdParseError::NotBase32),
        }
    }
}

/// Some principal ids have special classes (system-generated,
/// self-authenticating, derived), see https://sdk.dfinity.org/docs/interface-spec/index.html#id-classes
///
/// The following functions allow creating and testing for the special forms.
impl PrincipalId {
    const TYPE_OPAQUE: u8 = 0x01;
    const TYPE_SELF_AUTH: u8 = 0x02;
    const TYPE_DERIVED: u8 = 0x03;
    const TYPE_ANONYMOUS: u8 = 0x04;

    /// Opaque ids are usually used for system-internal ids (maybe system
    /// canisters, maybe test ids). Instead of using this directly, consider
    /// adding a separate constructor here for every such use case, so that
    /// one can easily check here that all such ids are disjoint.
    pub(crate) fn new_opaque(blob: &[u8]) -> Self {
        let mut bytes = blob.to_vec();
        bytes.push(Self::TYPE_OPAQUE);
        PrincipalId::try_from(&bytes[..]).unwrap()
    }

    /// Creates an opaque id from the first `len` bytes of `blob`.
    ///
    /// `len` must be _strictly_ less than `MAX_LENGTH_IN_BYTES` so that there
    /// is enough room for the suffix.
    pub(crate) const fn new_opaque_from_array(
        mut blob: [u8; Self::MAX_LENGTH_IN_BYTES],
        len: usize,
    ) -> Self {
        blob[len] = Self::TYPE_OPAQUE;
        PrincipalId::new(len + 1, blob)
    }

    pub fn new_user_test_id(n: u64) -> Self {
        let mut bytes = n.to_le_bytes().to_vec();
        bytes.push(0xfe); // internal marker for user test ids
        Self::new_opaque(&bytes[..])
    }
    pub fn new_node_test_id(n: u64) -> Self {
        let mut bytes = n.to_le_bytes().to_vec();
        bytes.push(0xfd); // internal marker for node test ids
        Self::new_opaque(&bytes[..])
    }
    pub fn new_subnet_test_id(n: u64) -> Self {
        let mut bytes = n.to_le_bytes().to_vec();
        bytes.push(0xfc); // internal marker for subnet test ids
        Self::new_opaque(&bytes[..])
    }

    pub const fn new(len: usize, data: [u8; Self::MAX_LENGTH_IN_BYTES]) -> Self {
        PrincipalId { len, data }
    }

    pub fn new_self_authenticating(pubkey: &[u8]) -> Self {
        let mut id: [u8; 29] = [0; 29];
        id[..28].copy_from_slice(&Sha224::hash(pubkey));
        id[28] = Self::TYPE_SELF_AUTH;
        PrincipalId {
            len: id.len(),
            data: id,
        }
    }

    pub fn new_derived(registerer: &PrincipalId, seed: &[u8]) -> Self {
        let mut blob: Vec<u8> = registerer.into_vec();
        blob.insert(0, blob.len() as u8);
        blob.extend(seed);
        let mut bytes = Sha224::hash(&blob[..]).to_vec();
        bytes.push(Self::TYPE_DERIVED);
        PrincipalId::try_from(&bytes[..]).unwrap()
    }

    pub fn new_anonymous() -> Self {
        let mut data = [0; Self::MAX_LENGTH_IN_BYTES];
        data[0] = Self::TYPE_ANONYMOUS;
        PrincipalId { len: 1, data }
    }

    pub fn authenticates_for_pubkey(&self, pubkey: &[u8]) -> bool {
        let blob = self.as_slice();
        if blob.len() != Self::HASH_LEN_IN_BYTES + 1 {
            return false;
        }
        if blob.last() != Some(&Self::TYPE_SELF_AUTH) {
            return false;
        }
        if Sha224::hash(pubkey) != blob[0..Self::HASH_LEN_IN_BYTES] {
            return false;
        }
        true
    }

    pub fn is_self_authenticating(&self) -> bool {
        let blob = self.as_slice();
        if blob.len() != Self::HASH_LEN_IN_BYTES + 1 {
            return false;
        }
        if blob.last() != Some(&Self::TYPE_SELF_AUTH) {
            return false;
        }
        true
    }

    pub fn is_derived(&self, registerer: &PrincipalId, seed: &[u8]) -> bool {
        PrincipalId::new_derived(registerer, seed) == *self
    }

    pub fn is_anonymous(&self) -> bool {
        self.len == 1 && self.data[0] == Self::TYPE_ANONYMOUS
    }
}

impl candid::CandidType for PrincipalId {
    fn id() -> TypeId {
        TypeId::of::<PrincipalId>()
    }
    fn _ty() -> Type {
        Type::Principal
    }
    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        serializer.serialize_principal(self.as_slice())
    }
}

impl From<&PrincipalId> for PrincipalIdProto {
    fn from(id: &PrincipalId) -> Self {
        PrincipalIdProto {
            serialized_id: id.as_slice().to_vec(),
        }
    }
}

impl From<&mut PrincipalId> for PrincipalIdProto {
    fn from(id: &mut PrincipalId) -> Self {
        PrincipalIdProto {
            serialized_id: id.as_slice().to_vec(),
        }
    }
}

impl From<PrincipalId> for PrincipalIdProto {
    fn from(id: PrincipalId) -> Self {
        PrincipalIdProto {
            serialized_id: id.as_slice().to_vec(),
        }
    }
}

impl From<PrincipalIdProto> for PrincipalId {
    fn from(pb: PrincipalIdProto) -> Self {
        PrincipalId::try_from(pb.serialized_id).unwrap()
    }
}

/// Encode/Decode a [`PrincipalId`] from/to protobuf.
///
/// This acts as a wrapper around the actual (prost generated)
/// protobuf type, which defines the pb on-wire format for
/// [`PrincipalId`]. Prost generated types can map this type instead
/// of the generated type and use it seamlessly, which is particularly
/// useful when those types are also candid types.
impl prost::Message for PrincipalId {
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: bytes::buf::BufMut,
    {
        let pid_proto = PrincipalIdProto::from(self);
        pid_proto.encode_raw(buf)
    }

    fn merge_field<B>(
        &mut self,
        tag: u32,
        wire_type: prost::encoding::WireType,
        buf: &mut B,
        ctx: prost::encoding::DecodeContext,
    ) -> std::result::Result<(), prost::DecodeError>
    where
        B: bytes::buf::Buf,
    {
        let mut pid_proto = PrincipalIdProto::from(*self);
        pid_proto.merge_field(tag, wire_type, buf, ctx)?;
        *self = Self::from(pid_proto);
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        PrincipalIdProto::from(self).encoded_len()
    }

    fn clear(&mut self) {
        let mut pid_proto = PrincipalIdProto::from(*self);
        pid_proto.clear();
        *self = Self::from(pid_proto);
    }
}

impl Serialize for PrincipalId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_bytes(self.as_slice())
    }
}

impl<'de> Deserialize<'de> for PrincipalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct PrincipalIdVisitor;

        impl<'de> serde::de::Visitor<'de> for PrincipalIdVisitor {
            type Value = PrincipalId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "a principal id: a blob with at most {} bytes",
                    PrincipalId::MAX_LENGTH_IN_BYTES
                )
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                PrincipalId::try_from(v).map_err(|err| E::custom(err.to_string()))
            }
            /// This visitor should only be used by the Candid crate.
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.is_empty() || v[0] != 2u8 {
                    Err(E::custom("Not called by Candid"))
                } else {
                    PrincipalId::try_from(&v[1..]).map_err(E::custom)
                }
            }
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use std::str::FromStr;
                PrincipalId::from_str(s).map_err(|err| E::custom(err.to_string()))
            }

            fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error;
                let mut bytes = Vec::with_capacity(PrincipalId::MAX_LENGTH_IN_BYTES);

                while let Some(b) = visitor.next_element()? {
                    bytes.push(b);
                }

                PrincipalId::try_from(&bytes[..]).map_err(|err| V::Error::custom(err.to_string()))
            }
        }

        deserializer.deserialize_bytes(PrincipalIdVisitor)
    }
}

impl From<PrincipalId> for pb::PrincipalId {
    fn from(id: PrincipalId) -> Self {
        Self { raw: id.into_vec() }
    }
}

impl TryFrom<pb::PrincipalId> for PrincipalId {
    type Error = PrincipalIdBlobParseError;

    fn try_from(value: pb::PrincipalId) -> Result<Self, Self::Error> {
        Self::try_from(&value.raw[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::vec as pvec;
    use proptest::prelude::*;
    use std::str::FromStr;

    fn arb_principal_id() -> BoxedStrategy<PrincipalId> {
        pvec(any::<u8>(), 0..PrincipalId::MAX_LENGTH_IN_BYTES)
            .prop_map(|b| PrincipalId::try_from(&b[..]).unwrap())
            .boxed()
    }

    proptest! {
        #[test]
        fn roundtrip_blob(id in arb_principal_id()) {
            let blob: Vec<u8> = id.to_vec();
            assert_eq!(PrincipalId::try_from(&blob[..]).unwrap(), id);
        }

        #[test]
        fn roundtrip_text(id in arb_principal_id()) {
            let text : String = id.to_string();
            assert_eq!(PrincipalId::from_str(&text[..]), Ok(id));
        }

        #[test]
        fn parse_from_str_does_not_crash(s in "\\PC*") {
            let _ignore = PrincipalId::from_str(&s[..]);
        }
    }

    #[test]
    fn parse_bad_checksum() {
        assert_eq!(
            PrincipalId::from_str(&"5h74t-uga73-7nadi".to_string()),
            Err(PrincipalIdParseError::Wrong {
                expected: "bfozs-kwa73-7nadi".to_string()
            })
        );
    }

    #[test]
    fn parse_too_short() {
        assert_eq!(
            PrincipalId::from_str(&"".to_string()),
            Err(PrincipalIdParseError::TooShort)
        );
        assert_eq!(
            PrincipalId::from_str(&"vpgq".to_string()),
            Err(PrincipalIdParseError::TooShort)
        );
    }

    #[test]
    fn parse_too_long() {
        assert_eq!(
            PrincipalId::from_str(
                "fmakz-kp753-o4zo5-ktgeh-ozsvi-qzsee-ia77x-n3tf3-vkmyq-53gkv-cdgiq"
            ),
            Err(PrincipalIdParseError::TooLong)
        )
    }

    #[test]
    fn parse_not_normalized() {
        assert_eq!(
            PrincipalId::from_str(&"BFOZS-KWA73-7NADI".to_string()),
            Err(PrincipalIdParseError::Wrong {
                expected: "bfozs-kwa73-7nadi".to_string()
            })
        );
        assert_eq!(
            PrincipalId::from_str(&"bfozskwa737nadi".to_string()),
            Err(PrincipalIdParseError::Wrong {
                expected: "bfozs-kwa73-7nadi".to_string()
            })
        );
        assert_eq!(
            PrincipalId::from_str(&"bf-oz-sk-wa737-nadi".to_string()),
            Err(PrincipalIdParseError::Wrong {
                expected: "bfozs-kwa73-7nadi".to_string()
            })
        );
    }

    /// Now the tests related to the special classes

    #[test]
    fn parse_opaque_id_ok() {
        assert_eq!(
            PrincipalId::from_str("2chl6-4hpzw-vqaaa-aaaaa-c"),
            Ok(PrincipalId::new_opaque(
                &[0xef, 0xcd, 0xab, 0x00, 0x00, 0x00, 0x00, 0x00][..]
            ))
        );
    }

    #[test]
    fn parse_self_authenticating_id_ok() {
        let key = [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];
        let id = PrincipalId::new_self_authenticating(&key);
        assert_eq!(
            PrincipalId::from_str(
                "bngem-gzprz-dtr6o-xnali-fgmfi-fjgpb-rya7j-x2idk-3eh6u-4v7tx-hqe"
            ),
            Ok(id)
        );
        assert!(id.authenticates_for_pubkey(&key));
    }

    #[test]
    fn parse_derived_id_ok() {
        let registerer = PrincipalId::try_from(
            &[
                0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
                0x33,
            ][..],
        )
        .unwrap();
        let seed = [0xdd, 0xcc, 0xbb, 0xaa, 0xdd, 0xcc, 0xbb, 0xaa];
        let id = PrincipalId::new_derived(&registerer, &seed);
        assert_eq!(
            PrincipalId::from_str(
                "c2u3y-w273i-ols77-om7wu-jzrdm-gxxz3-b75cc-3ajdg-mauzk-hm5vh-jag"
            ),
            Ok(id)
        );

        assert!(id.is_derived(&registerer, &seed));
    }

    #[test]
    fn parse_anonymous_id_ok() {
        assert!(PrincipalId::new_anonymous().is_anonymous());
        assert_eq!(
            PrincipalId::from_str("2vxsx-fae"),
            Ok(PrincipalId::new_anonymous())
        );
    }

    #[test]
    fn can_be_deserialized_from_blob() {
        let principal = PrincipalId::new_opaque(&[1, 2, 3, 4][..]);
        let cbor_bytes =
            serde_cbor::to_vec(&principal.to_vec()).expect("failed to serialize principal id");
        let parsed: PrincipalId =
            serde_cbor::from_slice(&cbor_bytes[..]).expect("failed to deserialize principal id");
        assert_eq!(principal, parsed);
    }
}
