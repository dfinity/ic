use std::{borrow::Cow, convert::TryInto};

use candid::{CandidType, Decode, Encode};
use ic_stable_structures::{
    storable::{Blob, Bound},
    Storable,
};
use serde::{Deserialize, Serialize};

pub type CanisterId = candid::Principal;

pub type KeyName = Blob<32>;
pub type MapName = KeyName;
pub type MapId = KeyId;
pub type KeyId = (candid::Principal, KeyName);
pub type MapKey = Blob<32>;
pub type TransportKey = ByteBuf;
pub type EncryptedMapValue = ByteBuf;

#[derive(Serialize, Deserialize)]
pub struct KeyManagerConfig {
    pub domain_separator: String,
    pub key_id: ic_cdk::management_canister::VetKDKeyId,
}

impl Storable for KeyManagerConfig {
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(serde_cbor::to_vec(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_cbor::from_slice(bytes.as_ref()).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}

/// Access rights of a user to a vetKey in [`crate::key_manager::KeyManager`] and/or an encrypted map in [`crate::encrypted_maps::EncryptedMaps`].
#[repr(u8)]
#[derive(
    CandidType,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    strum_macros::FromRepr,
    strum_macros::EnumIter,
)]
pub enum AccessRights {
    /// User can retrieve the vetKey or encrypted map.
    Read = 0,
    /// User can update values in the encrypted map.
    ReadWrite = 1,
    /// User can view/share/revoke access to the vetKey or encrypted map.
    ReadWriteManage = 2,
}

impl Storable for AccessRights {
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(vec![*self as u8])
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let v = <u8>::from_be_bytes(bytes.as_ref().try_into().unwrap());
        Self::from_repr(v).unwrap()
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 1,
        is_fixed_size: true,
    };
}

impl AccessControl for AccessRights {
    fn can_read(&self) -> bool {
        matches!(
            self,
            AccessRights::Read | AccessRights::ReadWrite | AccessRights::ReadWriteManage
        )
    }

    fn can_write(&self) -> bool {
        matches!(
            self,
            AccessRights::ReadWrite | AccessRights::ReadWriteManage
        )
    }

    fn can_get_user_rights(&self) -> bool {
        matches!(self, AccessRights::ReadWriteManage)
    }

    fn can_set_user_rights(&self) -> bool {
        matches!(self, AccessRights::ReadWriteManage)
    }

    fn owner_rights() -> Self {
        AccessRights::ReadWriteManage
    }
}

pub trait AccessControl:
    CandidType
    + Serialize
    + Clone
    + Copy
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + std::fmt::Debug
    + strum::IntoEnumIterator
    + Storable
{
    /// Returns if the user can read the vetKey or encrypted map.
    fn can_read(&self) -> bool;
    /// Returns if the user can write to the vetKey or encrypted map.
    fn can_write(&self) -> bool;
    /// Returns if the user can view the access rights to the vetKey or encrypted map.
    fn can_get_user_rights(&self) -> bool;
    /// Returns if the user can modify the access rights to the vetKey or encrypted map.
    fn can_set_user_rights(&self) -> bool;
    /// Returns the access rights of the owner of the vetKey or encrypted map.
    fn owner_rights() -> Self;
}

/// Efficiently serializable and deserializable byte vector that is `Storable` with `ic_stable_structures`.
/// See, e.g., [https://mmapped.blog/posts/01-effective-rust-canisters#serde-bytes](https://mmapped.blog/posts/01-effective-rust-canisters#serde-bytes) for more details regarding why `Vec<u8>` does not work out of the box.
/// Also, we cannot use `serde_bytes::ByteBuf` directly because it is not `Storable`.
#[derive(CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct ByteBuf {
    #[serde(with = "serde_bytes")]
    inner: Vec<u8>,
}

impl ByteBuf {
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }
}

impl From<Vec<u8>> for ByteBuf {
    fn from(inner: Vec<u8>) -> Self {
        Self { inner }
    }
}

impl From<ByteBuf> for Vec<u8> {
    fn from(buf: ByteBuf) -> Self {
        buf.inner
    }
}

impl AsRef<[u8]> for ByteBuf {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl Default for ByteBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl Storable for ByteBuf {
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}
