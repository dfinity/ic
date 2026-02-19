use candid::{CandidType, Principal};
use ic_stable_structures::storable::{Bound, Storable};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

macro_rules! storable_unbounded {
    ($name:ident) => {
        impl Storable for $name {
            fn to_bytes(&self) -> Cow<[u8]> {
                Cow::Owned(serde_cbor::to_vec(self).expect("failed to serialize"))
            }

            fn into_bytes(self) -> Vec<u8> {
                self.to_bytes().into_owned()
            }

            fn from_bytes(bytes: Cow<[u8]>) -> Self {
                serde_cbor::from_slice(&bytes).expect("failed to deserialize")
            }

            const BOUND: Bound = Bound::Unbounded;
        }
    };
}

macro_rules! storable_delegate {
    ($name:ident, $t:ident) => {
        impl Storable for $name {
            fn to_bytes(&self) -> Cow<'_, [u8]> {
                self.0.to_bytes()
            }

            fn into_bytes(self) -> Vec<u8> {
                self.0.into_bytes()
            }

            fn from_bytes(bytes: Cow<[u8]>) -> Self {
                $name($t::from_bytes(bytes))
            }

            const BOUND: Bound = $t::BOUND;
        }
    };
}

#[derive(CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct EncryptedMessage {
    pub content: Vec<u8>,
    pub metadata: EncryptedMessageMetadata,
}

storable_unbounded!(EncryptedMessage);

#[derive(CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct EncryptedMessageMetadata {
    pub sender: Principal,
    /// timestamp when the message was received by the canister - determines the symmetric key epoch
    pub timestamp: Time,
    pub vetkey_epoch: VetKeyEpochId,
    pub symmetric_key_epoch: SymmetricKeyEpochId,
    pub chat_message_id: ChatMessageId,
    pub nonce: Nonce,
}

impl Storable for EncryptedMessageMetadata {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.sender.as_slice());
        bytes.extend_from_slice(&self.timestamp.0.to_le_bytes());
        bytes.extend_from_slice(&self.vetkey_epoch.0.to_le_bytes());
        bytes.extend_from_slice(&self.symmetric_key_epoch.0.to_le_bytes());
        bytes.extend_from_slice(&self.chat_message_id.0.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.0.to_le_bytes());
        Cow::Owned(bytes)
    }

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }

    #[inline]
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let (sender_bytes, rest) = bytes.as_ref().split_at(Principal::MAX_LENGTH_IN_BYTES);
        let sender = Principal::from_slice(sender_bytes);

        let (timestamp_bytes, rest) = rest.split_at(8);
        let timestamp = Time(u64::from_le_bytes(timestamp_bytes.try_into().unwrap()));

        let (vetkey_epoch_bytes, rest) = rest.split_at(8);
        let vetkey_epoch =
            VetKeyEpochId(u64::from_le_bytes(vetkey_epoch_bytes.try_into().unwrap()));

        let (symmetric_key_epoch_bytes, rest) = rest.split_at(8);
        let symmetric_key_epoch = SymmetricKeyEpochId(u64::from_le_bytes(
            symmetric_key_epoch_bytes.try_into().unwrap(),
        ));

        let (chat_message_id_bytes, nonce_bytes) = rest.split_at(8);
        let chat_message_id = ChatMessageId(u64::from_le_bytes(
            chat_message_id_bytes.try_into().unwrap(),
        ));

        let nonce = Nonce(u64::from_le_bytes(nonce_bytes.try_into().unwrap()));

        Self {
            sender,
            timestamp,
            vetkey_epoch,
            symmetric_key_epoch,
            chat_message_id,
            nonce,
        }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: Principal::MAX_LENGTH_IN_BYTES as u32 + 4 * 8,
        is_fixed_size: false,
    };
}

#[derive(CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct UserMessage {
    pub content: Vec<u8>,
    pub vetkey_epoch: VetKeyEpochId,
    pub symmetric_key_epoch: SymmetricKeyEpochId,
    pub nonce: Nonce,
}

storable_unbounded!(UserMessage);

#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Copy,
)]
pub struct SymmetricKeyEpochId(pub u64);

storable_delegate!(SymmetricKeyEpochId, u64);

#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Copy,
)]
pub struct DirectChatId(pub(crate) Principal, pub(crate) Principal);

impl Storable for DirectChatId {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(
            self.0
                .as_slice()
                .iter()
                .chain(self.1.as_slice().iter())
                .cloned()
                .collect(),
        )
    }

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let (a_bytes, b_bytes) = bytes.as_ref().split_at(Principal::MAX_LENGTH_IN_BYTES);
        let a = Principal::from_slice(a_bytes);
        let b = Principal::from_slice(b_bytes);
        Self(a, b)
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 2 * Principal::MAX_LENGTH_IN_BYTES as u32,
        is_fixed_size: false,
    };
}

impl DirectChatId {
    pub fn new(participants: (Principal, Principal)) -> Self {
        let (a, b) = participants;
        let (a, b) = if a < b { (a, b) } else { (b, a) };
        Self(a, b)
    }
}

#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Copy,
)]
pub struct GroupChatMetadata {
    pub chat_id: GroupChatId,
    pub creation_timestamp: Time,
}

storable_unbounded!(GroupChatMetadata);

#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Copy,
)]
pub struct GroupChatId(pub u64);

storable_delegate!(GroupChatId, u64);

#[derive(CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct EncryptedSymmetricKeyEpochCache(#[serde(with = "serde_bytes")] pub Vec<u8>);

storable_unbounded!(EncryptedSymmetricKeyEpochCache);

#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Copy,
)]
pub struct Time(pub u64);

storable_delegate!(Time, u64);

#[derive(CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct VetKeyEpochMetadata {
    pub epoch_id: VetKeyEpochId,
    pub participants: Vec<Principal>,
    pub creation_timestamp: Time,
    pub symmetric_key_rotation_duration: Time,
    pub messages_start_with_id: ChatMessageId,
}

storable_unbounded!(VetKeyEpochMetadata);

#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Copy,
)]
pub enum ChatId {
    Direct(DirectChatId),
    Group(GroupChatId),
}

impl ChatId {
    pub const MIN_VALUE: Self = Self::Direct(DirectChatId(
        Principal::management_canister(),
        Principal::management_canister(),
    ));
}

impl Storable for ChatId {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let result = match self {
            ChatId::Direct(id) => [0].iter().chain(id.to_bytes().iter()).cloned().collect(),
            ChatId::Group(id) => [1].iter().chain(id.to_bytes().iter()).cloned().collect(),
        };

        Cow::Owned(result)
    }

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        match bytes.as_ref() {
            [0, ..] => ChatId::Direct(DirectChatId::from_bytes(Cow::Borrowed(
                &bytes.as_ref()[1..],
            ))),
            [1, ..] => ChatId::Group(GroupChatId::from_bytes(Cow::Borrowed(&bytes.as_ref()[1..]))),
            _ => panic!("invalid chat id"),
        }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 1 + 2 * Principal::MAX_LENGTH_IN_BYTES as u32,
        is_fixed_size: false,
    };
}

/// User-assigned nonce used for message encryption.
#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Copy,
)]
pub struct Nonce(pub u64);

storable_delegate!(Nonce, u64);

/// Chat message id is assigned to each message in the chat sequentially.
/// The IDs are assigned from an incrementing counter for a chat for all users.
/// This is useful because user's messages can arrive out of order (which makes user's IDs unreliable) or arrive many at the same consensus time.
/// Therefore, it's important to be able to provide convenient pagination of chat messages, s.t. a user can retrieve a longer chat history iteratively.
#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Copy,
)]
pub struct ChatMessageId(pub u64);

storable_delegate!(ChatMessageId, u64);

#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Copy,
)]
pub struct Sender(pub Principal);

storable_delegate!(Sender, Principal);

#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Copy,
)]
pub struct VetKeyEpochId(pub u64);

storable_delegate!(VetKeyEpochId, u64);

#[derive(CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct IbeEncryptedVetKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl Storable for IbeEncryptedVetKey {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.0.as_slice())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(bytes.into_owned())
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[derive(CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct GroupModification {
    pub add_participants: Vec<Principal>,
    pub remove_participants: Vec<Principal>,
}
