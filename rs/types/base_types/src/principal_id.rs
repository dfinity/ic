use crate::ic_types::{Principal, PrincipalError};
use crate::pb_internal::v1::PrincipalId as PrincipalIdProto;
use candid::types::{Type, TypeId};
use ic_crypto_sha::Sha224;
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    error::Error,
    fmt,
    hash::{Hash, Hasher},
};

/// The type representing principals as described in the [interface
/// spec](https://sdk.dfinity.org/docs/interface-spec/index.html#_principals).
///
/// A principal is just a blob that is displayed in a particular way.
/// (see https://sdk.dfinity.org/docs/interface-spec/index.html#textual-ids)
///
/// Principals have variable length, bounded by 29 bytes. Since we
/// want [`PrincipalId`] to implement the Copy trait, we encode them as
/// a fixed-size array and a length.
#[derive(Clone, Copy, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(
    feature = "test",
    derive(comparable::Comparable),
    describe_type(String),
    describe_body(self.to_string())
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct PrincipalId(#[cfg_attr(feature = "test", comparable_ignore)] pub Principal);

impl PartialEq for PrincipalId {
    fn eq(&self, other: &PrincipalId) -> bool {
        self.0 == other.0
    }
}

impl Hash for PrincipalId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let slice = self.0.as_slice();
        slice.len().hash(state);
        let mut array = [0; Self::MAX_LENGTH_IN_BYTES];
        array[..slice.len()].copy_from_slice(slice);
        array.hash(state);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct PrincipalIdError(pub PrincipalError);

impl PrincipalIdError {
    #[allow(non_snake_case)]
    pub fn TooLong(_: usize) -> Self {
        PrincipalIdError(PrincipalError::BufferTooLong())
    }
}

impl Error for PrincipalIdError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl fmt::Display for PrincipalIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for PrincipalId {
    fn default() -> Self {
        PrincipalId(Principal::management_canister())
    }
}

impl From<Principal> for PrincipalId {
    fn from(p: Principal) -> PrincipalId {
        PrincipalId(p)
    }
}
impl From<PrincipalId> for Principal {
    fn from(p: PrincipalId) -> Principal {
        p.0
    }
}

impl PrincipalId {
    pub const MAX_LENGTH_IN_BYTES: usize = 29;
    const HASH_LEN_IN_BYTES: usize = 28;

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.to_vec()
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<PrincipalId> for Vec<u8> {
    fn from(val: PrincipalId) -> Self {
        val.to_vec()
    }
}

/// The [`TryFrom`] trait should only be used when parsing data; fresh ids
/// should always be created with the functions below (PrincipalId::new_*)
impl TryFrom<&[u8]> for PrincipalId {
    type Error = PrincipalIdError;

    fn try_from(blob: &[u8]) -> Result<Self, Self::Error> {
        Principal::try_from(blob)
            .map(Self)
            .map_err(PrincipalIdError)
    }
}

impl TryFrom<Vec<u8>> for PrincipalId {
    type Error = PrincipalIdError;

    fn try_from(blob: Vec<u8>) -> Result<Self, Self::Error> {
        Principal::try_from(blob)
            .map(Self)
            .map_err(PrincipalIdError)
    }
}
impl TryFrom<&Vec<u8>> for PrincipalId {
    type Error = PrincipalIdError;

    fn try_from(blob: &Vec<u8>) -> Result<Self, Self::Error> {
        Principal::try_from(blob)
            .map(Self)
            .map_err(PrincipalIdError)
    }
}

impl AsRef<[u8]> for PrincipalId {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::str::FromStr for PrincipalId {
    type Err = PrincipalIdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Principal::from_str(input)
            .map(Self)
            .map_err(PrincipalIdError)
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
        PrincipalId(Principal::from_slice(&bytes[..]))
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
        // Calls in constant functions are limited to constant functions,
        // tuple structs and tuple variants (E0015)
        use std::ops::Range;
        const fn get(mut data: &[u8], r: Range<usize>) -> Option<&[u8]> {
            if r.start > r.end || data.len() < r.end {
                return None;
            }

            while data.len() > r.end {
                match data {
                    [x @ .., _] => data = x,
                    [] => {} //unreachable!(),
                }
            }

            while data.len() > r.end - r.start {
                match data {
                    [_, x @ ..] => data = x,
                    [] => {} //unreachable!(),
                }
            }

            Some(data)
        }
        pub const fn range(data: &[u8], r: Range<usize>) -> &[u8] {
            let (start, end) = (r.start, r.end);
            match get(data, r) {
                Some(v) => v,
                None => {
                    // TODO: remove (blocked by rust-lang/rust#85194)
                    // Give good panic messages
                    let _ = &data[start];
                    let _ = &data[end];
                    let _ = &data[end - start];
                    const ASSERT: [(); 1] = [()];
                    #[allow(unconditional_panic)]
                    let _ = ASSERT[1];

                    data
                }
            }
        }

        //PrincipalId(Principal::from_slice(&data[0..len]))
        PrincipalId(Principal::from_slice(range(&data, 0..len)))
    }

    pub fn new_self_authenticating(pubkey: &[u8]) -> Self {
        let mut id: [u8; 29] = [0; 29];
        id[..28].copy_from_slice(&Sha224::hash(pubkey));
        id[28] = Self::TYPE_SELF_AUTH;
        PrincipalId(Principal::from_slice(&id))
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
        PrincipalId(Principal::anonymous())
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
        self.as_slice() == [Self::TYPE_ANONYMOUS]
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

impl From<PrincipalId> for pb::PrincipalId {
    fn from(id: PrincipalId) -> Self {
        Self { raw: id.into_vec() }
    }
}

impl TryFrom<pb::PrincipalId> for PrincipalId {
    type Error = PrincipalIdError;

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
        prop_oneof![
            Just(PrincipalId(Principal::management_canister())), // `[]`
            Just(PrincipalId::new_anonymous()),                  // `[ANONYMOUS]`
            pvec(0..u8::MAX - 1, 1..PrincipalId::MAX_LENGTH_IN_BYTES).prop_map(|mut b| {
                // it's illegal for non-anonymous principals to end in `ANONYMOUS`
                // so remap trailing `ANONYMOUS` bytes
                const ANONYMOUS: u8 = 4;
                let last = b.last_mut().unwrap();
                if *last == ANONYMOUS {
                    *last = u8::MAX
                }
                PrincipalId::try_from(&b[..]).unwrap()
            }),
        ]
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
        let good =
            PrincipalId::from_str("bfozs-kwa73-7nadi").expect("PrincipalId::from_str failed");
        assert_eq!(
            PrincipalId::from_str("5h74t-uga73-7nadi"),
            Err(PrincipalIdError(PrincipalError::AbnormalTextualFormat(
                good.into()
            )))
        );
    }

    #[test]
    fn parse_too_short() {
        assert_eq!(
            PrincipalId::from_str(""),
            Err(PrincipalIdError(PrincipalError::TextTooSmall()))
        );
        assert_eq!(
            PrincipalId::from_str("vpgq"),
            Err(PrincipalIdError(PrincipalError::TextTooSmall()))
        );
    }

    #[test]
    fn parse_too_long() {
        assert_eq!(
            PrincipalId::from_str(
                "fmakz-kp753-o4zo5-ktgeh-ozsvi-qzsee-ia77x-n3tf3-vkmyq-53gkv-cdgiq"
            ),
            Err(PrincipalIdError(PrincipalError::BufferTooLong()))
        )
    }

    #[test]
    fn parse_not_normalized() {
        let good =
            PrincipalId::from_str("bfozs-kwa73-7nadi").expect("PrincipalId::from_str failed");
        assert_eq!(
            PrincipalId::from_str("BFOZS-KWA73-7NADI"),
            Err(PrincipalIdError(PrincipalError::AbnormalTextualFormat(
                good.into()
            )))
        );
        assert_eq!(
            PrincipalId::from_str("bfozskwa737nadi"),
            Err(PrincipalIdError(PrincipalError::AbnormalTextualFormat(
                good.into()
            )))
        );
        assert_eq!(
            PrincipalId::from_str("bf-oz-sk-wa737-nadi"),
            Err(PrincipalIdError(PrincipalError::AbnormalTextualFormat(
                good.into()
            )))
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
        let cbor_bytes = serde_cbor::to_vec(&principal).expect("failed to serialize principal id");
        let parsed: PrincipalId =
            serde_cbor::from_slice(&cbor_bytes[..]).expect("failed to deserialize principal id");
        assert_eq!(principal, parsed);
    }

    #[test]
    fn sorts_correctly() {
        let mut v = vec![
            PrincipalId::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap(),
            PrincipalId::from_str(
                "c2u3y-w273i-ols77-om7wu-jzrdm-gxxz3-b75cc-3ajdg-mauzk-hm5vh-jag",
            )
            .unwrap(),
            PrincipalId::try_from(&[3, 0, 0, 0, 0, 0, 0, 0, 253, 1][..]).unwrap(),
            PrincipalId::from_str("bfozs-kwa73-7nadi").unwrap(),
            PrincipalId::from_str("aaaaa-aa").unwrap(),
            PrincipalId::from_str("2vxsx-fae").unwrap(),
            PrincipalId::try_from(&[4, 0, 0, 0, 0, 0, 0, 0, 253, 1][..]).unwrap(),
            PrincipalId::try_from(&[0, 0, 0, 0, 0, 0, 0, 0, 253, 1][..]).unwrap(),
            PrincipalId::try_from(&[1, 0, 0, 0, 0, 0, 0, 0, 253, 1][..]).unwrap(),
        ];
        v.sort_unstable();
        assert_eq!(
            v,
            vec![
                PrincipalId::from_str("aaaaa-aa").unwrap(),
                PrincipalId::from_str("2vxsx-fae").unwrap(),
                PrincipalId::from_str("bfozs-kwa73-7nadi").unwrap(),
                PrincipalId::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap(),
                PrincipalId::try_from(&[0, 0, 0, 0, 0, 0, 0, 0, 253, 1][..]).unwrap(),
                PrincipalId::try_from(&[1, 0, 0, 0, 0, 0, 0, 0, 253, 1][..]).unwrap(),
                PrincipalId::try_from(&[3, 0, 0, 0, 0, 0, 0, 0, 253, 1][..]).unwrap(),
                PrincipalId::try_from(&[4, 0, 0, 0, 0, 0, 0, 0, 253, 1][..]).unwrap(),
                PrincipalId::from_str(
                    "c2u3y-w273i-ols77-om7wu-jzrdm-gxxz3-b75cc-3ajdg-mauzk-hm5vh-jag"
                )
                .unwrap(),
            ]
        );
    }

    #[test]
    fn hashes_correctly() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn calculate_hash<T: Hash>(t: &T) -> u64 {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        }
        fn hash_id_string(s: &str) -> u64 {
            calculate_hash(&PrincipalId::from_str(s).unwrap())
        }
        fn hash_id_slice(v: &[u8]) -> u64 {
            calculate_hash(&PrincipalId::try_from(v).unwrap())
        }

        assert_eq!(hash_id_string("aaaaa-aa"), 7819764810086413800);
        assert_eq!(hash_id_string("2vxsx-fae"), 265120109611795366);
        assert_eq!(hash_id_string("bfozs-kwa73-7nadi"), 5239847422961869918);
        assert_eq!(
            hash_id_string("2chl6-4hpzw-vqaaa-aaaaa-c"),
            4991410779248500671
        );
        assert_eq!(
            hash_id_string("c2u3y-w273i-ols77-om7wu-jzrdm-gxxz3-b75cc-3ajdg-mauzk-hm5vh-jag"),
            15210277524485168571
        );

        assert_eq!(
            hash_id_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 253, 1]),
            727338461816966860
        );
        assert_eq!(
            hash_id_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 253, 1]),
            297900807593556648
        );
        assert_eq!(
            hash_id_slice(&[3, 0, 0, 0, 0, 0, 0, 0, 253, 1]),
            11403466979739875017
        );
        assert_eq!(
            hash_id_slice(&[4, 0, 0, 0, 0, 0, 0, 0, 253, 1]),
            7553483959829495483
        );
    }
}
