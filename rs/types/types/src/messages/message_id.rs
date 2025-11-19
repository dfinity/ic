use super::RawHttpRequestVal;
use crate::{CountBytes, crypto::SignedBytesWithoutDomainSeparator};
use ic_base_types::hash_of_map;
use ic_crypto_sha2::Sha256;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::proxy::ProxyDecodeError;
use serde::{Deserialize, Serialize, de::Deserializer, ser::Serializer};
use std::{
    convert::{AsRef, TryFrom},
    error::Error,
    fmt,
};

/// The length of a [`MessageId`] is 32: `<https://internetcomputer.org/docs/current/references/ic-interface-spec#request-id>`
pub const EXPECTED_MESSAGE_ID_LENGTH: usize = 32;

/// The ID used to uniquely identify a user's ingress message.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct MessageId([u8; EXPECTED_MESSAGE_ID_LENGTH]);

// Because we can't use #[serde(with = "serde_bytes")] with derive(Deserialize)
// for [u8; 32], we have to implement Serialize/Deserialize manually.
impl Serialize for MessageId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'a> Deserialize<'a> for MessageId {
    fn deserialize<D: Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        struct MessageIdVisitor;

        impl serde::de::Visitor<'_> for MessageIdVisitor {
            type Value = MessageId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "a message id: a blob with with {EXPECTED_MESSAGE_ID_LENGTH} bytes"
                )
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut bytes: [u8; EXPECTED_MESSAGE_ID_LENGTH] = Default::default();
                bytes.copy_from_slice(v);
                Ok(MessageId(bytes))
            }
        }

        deserializer.deserialize_bytes(MessageIdVisitor)
    }
}

impl CountBytes for MessageId {
    fn count_bytes(&self) -> usize {
        self.0.len()
    }
}

impl MessageId {
    pub fn as_bytes(&self) -> &[u8; EXPECTED_MESSAGE_ID_LENGTH] {
        &self.0
    }
}

impl SignedBytesWithoutDomainSeparator for MessageId {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl TryFrom<&[u8]> for MessageId {
    type Error = MessageIdError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == EXPECTED_MESSAGE_ID_LENGTH {
            let mut array = [0; EXPECTED_MESSAGE_ID_LENGTH];
            array.copy_from_slice(bytes);
            Ok(MessageId(array))
        } else {
            Err(MessageIdError::InvalidLength {
                given_length: bytes.len(),
                expected_length: EXPECTED_MESSAGE_ID_LENGTH,
            })
        }
    }
}

impl AsRef<[u8]> for MessageId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; EXPECTED_MESSAGE_ID_LENGTH]> for MessageId {
    fn from(bytes: [u8; EXPECTED_MESSAGE_ID_LENGTH]) -> Self {
        MessageId(bytes)
    }
}

fn hash_string(value: &str) -> Vec<u8> {
    Sha256::hash(value.as_bytes()).to_vec()
}

fn hash_bytes<T: AsRef<[u8]>>(value: T) -> Vec<u8> {
    Sha256::hash(value.as_ref()).to_vec()
}

fn hash_u64(value: u64) -> Vec<u8> {
    // We need at most ⌈ 64 / 7 ⌉ = 10 bytes to encode a 64 bit
    // integer in LEB128.
    let mut buf = [0u8; 10];
    let mut n = value;
    let mut i = 0;

    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;

        if n == 0 {
            buf[i] = byte;
            break;
        } else {
            buf[i] = byte | 0x80;
            i += 1;
        }
    }

    hash_bytes(&buf[..=i])
}

// arrays, encoded as the concatenation of the hashes of the encodings of the
// array elements.
fn hash_array(elements: &[RawHttpRequestVal]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    elements
        .iter()
        // Hash the encoding of all the array elements.
        .for_each(|e| hasher.write(hash_val(e).as_slice()));
    hasher.finish().to_vec() // hash the concatenation of the hashes.
}

fn hash_val(val: &RawHttpRequestVal) -> Vec<u8> {
    match val {
        RawHttpRequestVal::String(string) => hash_string(string),
        RawHttpRequestVal::Bytes(bytes) => hash_bytes(bytes),
        RawHttpRequestVal::U64(integer) => hash_u64(*integer),
        RawHttpRequestVal::Array(elements) => hash_array(elements),
        RawHttpRequestVal::Map(map) => {
            hash_of_map(map, |key, value| hash_key_val(key.as_str(), value)).to_vec()
        }
    }
}

pub(crate) fn hash_key_val(key: &str, val: &RawHttpRequestVal) -> Vec<u8> {
    let mut key_hash = hash_string(key);
    let mut val_hash = hash_val(val);
    key_hash.append(&mut val_hash);
    key_hash
}

impl From<&MessageId> for u32 {
    fn from(message_id: &MessageId) -> u32 {
        (message_id.0[0] as u32)
            | ((message_id.0[1] as u32) << 8)
            | ((message_id.0[2] as u32) << 16)
            | ((message_id.0[3] as u32) << 24)
    }
}

/// Errors returned when converting to a [`MessageId`] from a blob.
#[derive(Clone, Debug, Serialize)]
pub enum MessageIdError {
    /// Conversion to MessageId failed because the source did not contain the
    /// right number of bytes.
    InvalidLength {
        given_length: usize,
        expected_length: usize,
    },
}

impl fmt::Display for MessageIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                given_length,
                expected_length,
            } => write!(
                f,
                "Expected a message id of length {expected_length} bytes, but got {given_length} bytes instead."
            ),
        }
    }
}

impl Error for MessageIdError {}

impl From<MessageIdError> for ProxyDecodeError {
    fn from(err: MessageIdError) -> Self {
        match err {
            MessageIdError::InvalidLength {
                given_length,
                expected_length,
            } => ProxyDecodeError::InvalidMessageId {
                expected: expected_length,
                actual: given_length,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope, RawHttpRequestVal,
        SignedIngress,
    };
    use super::*;
    use crate::{CanisterId, PrincipalId, Time, time::expiry_time_from_now};
    use hex_literal::hex;

    #[test]
    /// The test covers all the supported values of `RawHttpRequestVal` and calculates the `hash_of_map` for a nested map.
    /// The expected hash serves as a guard against any future changes to the `hash_of_map` function, ensuring its stability.
    fn test_hash_of_map() {
        use RawHttpRequestVal::*;
        use maplit::btreemap;

        let inner_map_0 = btreemap! {
            "key_string_0".to_string() => String("test_string_0".to_string()),
        };
        let inner_map_1 = btreemap! {
            "key_string_1".to_string() => String("test_string_1".to_string()),
        };
        let inner_map_2 = btreemap! {
            "key_string_2".to_string() => String("test_string_2".to_string()),
        };

        let outer_map = btreemap! {
            "key_bytes".to_string() => Bytes(vec![1; 10]),
            "key_string".to_string() => String("test_string".to_string()),
            "key_u64".to_string() => U64(42),
            "key_array".to_string() => Array(vec![Map(inner_map_0), Map(inner_map_1)]),
            "key_inner".to_string() => Map(inner_map_2)
        };

        assert_eq!(
            hash_of_map(&outer_map, |key, value| { hash_key_val(key, value) }),
            hex!("ace3c6e84b170c6235faff2ee1152d831c332a7e3c932fb7d129f973d6913ff2")
        );
    }

    #[test]
    fn message_id_icf_key_val_reference_1() {
        assert_eq!(
            hash_key_val(
                "request_type",
                &RawHttpRequestVal::String("call".to_string())
            ),
            hex!(
                "
                769e6f87bdda39c859642b74ce9763cdd37cb1cd672733e8c54efaa33ab78af9
                7edb360f06acaef2cc80dba16cf563f199d347db4443da04da0c8173e3f9e4ed
                "
            )
            .to_vec()
        );
    }

    #[test]
    fn message_id_u64_id_reference() {
        assert_eq!(
            // LEB128: 0x00
            hash_u64(0),
            hex!("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
        );

        assert_eq!(
            // LEB128: 0xd2 0x09
            hash_u64(1234),
            hex!("8b37fd3ebbe6396a89ed8563dd0cc55927ac90138950460c77cffeb55cf63810"),
        );

        assert_eq!(
            // LEB128 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0x01
            hash_u64(0xffff_ffff_ffff_ffff),
            hex!("51672ea45f3539654bf9193f4ff763d90022eee7df5f5b76353d6f11a9eaccec"),
        )
    }

    #[test]
    fn message_id_string_reference_1() {
        assert_eq!(
            hash_string("request_type"),
            hex!("769e6f87bdda39c859642b74ce9763cdd37cb1cd672733e8c54efaa33ab78af9"),
        );
    }

    #[test]
    fn message_id_string_reference_2() {
        assert_eq!(
            hash_string("call"),
            hex!("7edb360f06acaef2cc80dba16cf563f199d347db4443da04da0c8173e3f9e4ed"),
        );
    }

    #[test]
    fn message_id_string_reference_3() {
        assert_eq!(
            hash_string("callee"),
            hex!("92ca4c0ced628df1e7b9f336416ead190bd0348615b6f71a64b21d1b68d4e7e2"),
        );
    }

    #[test]
    fn message_id_string_reference_4() {
        assert_eq!(
            hash_string("method_name"),
            hex!("293536232cf9231c86002f4ee293176a0179c002daa9fc24be9bb51acdd642b6"),
        );
    }

    #[test]
    fn message_id_string_reference_5() {
        assert_eq!(
            hash_string("hello"),
            hex!("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
        );
    }

    #[test]
    fn message_id_string_reference_6() {
        assert_eq!(
            hash_string("arg"),
            hex!("b25f03dedd69be07f356a06fe35c1b0ddc0de77dcd9066c4be0c6bbde14b23ff"),
        );
    }

    #[test]
    fn message_id_array_reference_1() {
        assert_eq!(
            hash_array(&[RawHttpRequestVal::String("a".to_string())]),
            // hash(hash("a"))
            hex!("bf5d3affb73efd2ec6c36ad3112dd933efed63c4e1cbffcfa88e2759c144f2d8"),
        );
    }

    #[test]
    fn message_id_array_reference_2() {
        assert_eq!(
            hash_array(&[
                RawHttpRequestVal::String("a".to_string()),
                RawHttpRequestVal::String("b".to_string()),
            ]),
            // hash(concat(hash("a"), hash("b"))
            hex!("e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a"),
        );
    }

    #[test]
    fn message_id_array_reference_3() {
        assert_eq!(
            hash_array(&[
                RawHttpRequestVal::Bytes(vec![97]), // "a" as a byte string.
                RawHttpRequestVal::String("b".to_string()),
            ]),
            // hash(concat(hash("a"), hash("b"))
            hex!("e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a"),
        );
    }

    #[test]
    fn message_id_array_reference_4() {
        assert_eq!(
            hash_array(&[RawHttpRequestVal::Array(vec![RawHttpRequestVal::String(
                "a".to_string()
            )])]),
            // hash(hash(hash("a"))
            hex!("eb48bdfa15fc43dbea3aabb1ee847b6e69232c0f0d9705935e50d60cce77877f"),
        );
    }

    #[test]
    fn message_id_array_reference_5() {
        assert_eq!(
            hash_array(&[RawHttpRequestVal::Array(vec![
                RawHttpRequestVal::String("a".to_string()),
                RawHttpRequestVal::String("b".to_string())
            ])]),
            // hash(hash(concat(hash("a"), hash("b")))
            hex!("029fd80ca2dd66e7c527428fc148e812a9d99a5e41483f28892ef9013eee4a19"),
        );
    }

    #[test]
    fn message_id_array_reference_6() {
        assert_eq!(
            hash_array(&[
                RawHttpRequestVal::Array(vec![
                    RawHttpRequestVal::String("a".to_string()),
                    RawHttpRequestVal::String("b".to_string())
                ]),
                RawHttpRequestVal::Bytes(vec![97]), // "a" in bytes
            ]),
            // hash(concat(hash(concat(hash("a"), hash("b")), hash(100))
            hex!("aec3805593d9ec6df50da070597f73507050ce098b5518d0456876701ada7bb7"),
        );
    }

    #[test]
    fn message_id_bytes_reference() {
        assert_eq!(
            // D    I    D    L    \0   \253 *"
            // 68   73   68   76   0    253  42
            hash_bytes([68, 73, 68, 76, 0, 253, 42]),
            hex!("6c0b2ae49718f6995c02ac5700c9c789d7b7862a0d53e6d40a73f1fcd2f70189")
        );
    }

    // Note that we explicitly don't want to use
    // `ic_test_utilities::SignedIngressBuilder` because that results in a "cyclic"
    // dependency that prevents incremental rust builds from working.
    fn signed_ingress(
        receiver: CanisterId,
        method_name: String,
        method_payload: Vec<u8>,
        expiry_time: Time,
        sender_sig: Vec<u8>,
        sender_pubkey: Vec<u8>,
    ) -> SignedIngress {
        let update = HttpCanisterUpdate {
            canister_id: Blob(receiver.get().into_vec()),
            method_name,
            arg: Blob(method_payload),
            sender: Blob(vec![0; 29]),
            ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            nonce: None,
        };
        let content = HttpCallContent::Call { update };
        let envelope = HttpRequestEnvelope::<HttpCallContent> {
            content,
            sender_pubkey: Some(Blob(sender_pubkey)),
            sender_sig: Some(Blob(sender_sig)),
            sender_delegation: None,
        };
        SignedIngress::try_from(envelope).unwrap()
    }

    #[test]
    /// This test ensures that the sender's signature and public keys are not
    /// taken into account when computing the MessageId.  It computes MessageIds
    /// on two messages containing different public keys and signatures and
    /// asserts that the computed MessageIds should be the same.
    fn message_id_icf_reference() {
        let expiry_time = expiry_time_from_now();
        let signed_ingress1 = signed_ingress(
            CanisterId::unchecked_from_principal(
                PrincipalId::try_from(&[0, 0, 0, 0, 0, 0, 4, 210][..]).unwrap(),
            ),
            "hello".to_string(),
            b"DIDL\x00\xFD*".to_vec(),
            expiry_time,
            vec![3; 32],
            vec![6; 32],
        );
        let message_id1 = signed_ingress1.id();
        let signed_ingress2 = signed_ingress(
            CanisterId::unchecked_from_principal(
                PrincipalId::try_from(&[0, 0, 0, 0, 0, 0, 4, 210][..]).unwrap(),
            ),
            "hello".to_string(),
            b"DIDL\x00\xFD*".to_vec(),
            expiry_time,
            vec![1; 32],
            vec![5; 32],
        );
        let message_id2 = signed_ingress2.id();
        assert_eq!(message_id1, message_id2);
    }

    #[test]
    fn message_id_deserialize() {
        let id = MessageId::from(hex!(
            "6a30017bd93e97a68eb17251dc2d45c4f6f507019c6f684f1dc340dc5d10c832"
        ));
        let value = bincode::serialize(&id);
        assert!(value.is_ok());
        let bytes = value.unwrap();
        let value = bincode::deserialize::<MessageId>(&bytes);
        assert!(value.is_ok());
        assert_eq!(value.unwrap(), id);
    }
}
