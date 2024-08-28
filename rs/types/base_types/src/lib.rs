//! A crate containing various basic types that are especially useful when
//! writing Rust canisters.

use ic_protobuf::proxy::try_from_option_field;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::types::v1 as pb;
use phantom_newtype::{AmountOf, DisplayerOf, Id};
use std::{convert::TryFrom, fmt};

mod canister_id;
mod pb_internal;
mod principal_id;

pub use canister_id::{CanisterId, CanisterIdError, CanisterIdError as CanisterIdBlobParseError};
use ic_protobuf::state::canister_state_bits::v1::SnapshotId as pbSnapshot;
pub use principal_id::{
    Class as PrincipalIdClass, PrincipalId, PrincipalIdError, PrincipalIdError as
    PrincipalIdBlobParseError, PrincipalIdError as PrincipalIdParseError,
};

pub struct RegistryVersionTag {}
/// A type representing the registry's version.
pub type RegistryVersion = AmountOf<RegistryVersionTag, u64>;

pub struct NodeTag {}
/// A type representing a node's [`PrincipalId`].
pub type NodeId = Id<NodeTag, PrincipalId>;

pub struct SubnetTag {}
/// A type representing a subnet's [`PrincipalId`].
pub type SubnetId = Id<SubnetTag, PrincipalId>;

pub struct NumSecondsTag;

/// Models a non-negative number of seconds.
pub type NumSeconds = AmountOf<NumSecondsTag, u64>;

pub struct NumBytesTag;
/// This type models a non-negative number of bytes.
///
/// This type is primarily useful in the context of tracking the memory usage
/// and allocation of a Canister.
pub type NumBytes = AmountOf<NumBytesTag, u64>;

pub enum NumOsPagesTag {}
/// A number of OS-sized pages.
pub type NumOsPages = AmountOf<NumOsPagesTag, u64>;

impl DisplayerOf<NumBytes> for NumBytesTag {
    /// Formats the number of bytes using the most appropriate binary power unit
    /// (kiB, MiB, GiB, etc), with up 2 decimals (e.g., 123.45 MiB).
    ///
    /// There will be no decimals iff the chosen unit is 'bytes'.
    fn display(num_bytes: &NumBytes, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            byte_unit::Byte::from_bytes(num_bytes.get().into())
                .get_appropriate_unit(true)
                .format(2)
        )
    }
}

/// Converts a SubnetId into its protobuf definition.  Normally, we would use
/// `impl From<SubnetId> for pb::SubnetId` here however we cannot as both
/// `Id` and `pb::SubnetId` are defined in other crates.
pub fn subnet_id_into_protobuf(id: SubnetId) -> pb::SubnetId {
    pb::SubnetId {
        principal_id: Some(pb::PrincipalId::from(id.get())),
    }
}

/// From its protobuf definition convert to a SubnetId.  Normally, we would
/// use `impl TryFrom<pb::SubnetId> for SubnetId` here however we cannot as
/// both `Id` and `pb::SubnetId` are defined in other crates.
pub fn subnet_id_try_from_protobuf(value: pb::SubnetId) -> Result<SubnetId, ProxyDecodeError> {
    let principal_id = PrincipalId::try_from(
        value
            .principal_id
            .ok_or(ProxyDecodeError::MissingField("SubnetId::principal_id"))?,
    )?;
    Ok(SubnetId::from(principal_id))
}

/// From its protobuf definition convert to a SubnetId.  Normally, we would
/// use `impl TryFrom<Option<pb::SubnetId>> for SubnetId` here however we cannot
/// as both `Id` and `pb::SubnetId` are defined in other crates.
pub fn subnet_id_try_from_option(
    value: Option<pb::SubnetId>,
) -> Result<SubnetId, ProxyDecodeError> {
    let value: pb::SubnetId = value.ok_or(ProxyDecodeError::MissingField("SubnetId"))?;
    let principal_id: PrincipalId =
        try_from_option_field(value.principal_id, "SubnetId::PrincipalId")?;
    Ok(SubnetId::from(principal_id))
}

impl From<PrincipalIdError> for ProxyDecodeError {
    fn from(err: PrincipalIdError) -> Self {
        Self::InvalidPrincipalId(Box::new(err))
    }
}

impl From<CanisterIdError> for ProxyDecodeError {
    fn from(err: CanisterIdError) -> Self {
        Self::InvalidCanisterId(Box::new(err))
    }
}

/// Represents an error that can occur when constructing a [`SnapshotId`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum SnapshotIdError {
    /// A [`SnapshotID`] with invalid length was given.
    InvalidLength(String),
    /// A [`SnapshotID`] with invalid format was given.
    InvalidFormat(String),
}

impl fmt::Display for SnapshotIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(err) => write!(f, "Invalid length of SnapshotId: {}", err),
            Self::InvalidFormat(err) => write!(f, "Invalid format of SnapshotId: {}", err,),
        }
    }
}

/// A type representing a canister's snapshot ID.
/// The ID is unique across all subnets.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct SnapshotId {
    /// The length of the canister ID.
    len: usize,
    // The field is computed based on the:
    //      - canister local snapshot ID,
    //      - canister ID.
    bytes: [u8; Self::MAX_LENGTH_IN_BYTES],
}

impl SnapshotId {
    pub const MAX_LENGTH_IN_BYTES: usize =
        PrincipalId::MAX_LENGTH_IN_BYTES + Self::LOCAL_ID_LENGTH_IN_BYTES;
    pub const LOCAL_ID_LENGTH_IN_BYTES: usize = 8;

    pub fn get_canister_id(&self) -> CanisterId {
        // Safe to unwrap, validated during `SnapshotId` creation.
        CanisterId::try_from(
            &self.bytes[Self::LOCAL_ID_LENGTH_IN_BYTES..Self::LOCAL_ID_LENGTH_IN_BYTES + self.len],
        )
        .unwrap()
    }

    pub fn get_local_snapshot_id(&self) -> u64 {
        let mut slice = [0u8; 8];
        slice.copy_from_slice(&self.bytes[..Self::LOCAL_ID_LENGTH_IN_BYTES]);
        u64::from_be_bytes(slice)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..Self::LOCAL_ID_LENGTH_IN_BYTES + self.len]
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl From<(CanisterId, u64)> for SnapshotId {
    fn from(item: (CanisterId, u64)) -> Self {
        let (canister_id, local_id) = item;
        // Specify explicitly the length, so as to assert at compile time that a u64
        // takes exactly 8 bytes
        let val: [u8; 8] = local_id.to_be_bytes();

        let mut bytes = [0u8; Self::MAX_LENGTH_IN_BYTES];
        bytes[..Self::LOCAL_ID_LENGTH_IN_BYTES].copy_from_slice(&val);

        let len = canister_id.get().as_slice().len();
        bytes[Self::LOCAL_ID_LENGTH_IN_BYTES..Self::LOCAL_ID_LENGTH_IN_BYTES + len]
            .copy_from_slice(canister_id.get().as_slice());

        Self { bytes, len }
    }
}

impl TryFrom<&Vec<u8>> for SnapshotId {
    type Error = SnapshotIdError;
    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() < Self::LOCAL_ID_LENGTH_IN_BYTES {
            return Err(SnapshotIdError::InvalidLength(format!(
                "Invalid snapshot ID length: provided {}, minumum length expected {}.",
                bytes.len(),
                Self::MAX_LENGTH_IN_BYTES
            )));
        }
        if bytes.len() > Self::MAX_LENGTH_IN_BYTES {
            return Err(SnapshotIdError::InvalidLength(format!(
                "Invalid snapshot ID length: provided {}, maximum length expected {}.",
                bytes.len(),
                Self::MAX_LENGTH_IN_BYTES
            )));
        }

        let canister_id =
            CanisterId::try_from(&bytes[Self::LOCAL_ID_LENGTH_IN_BYTES..]).map_err(|_| {
                SnapshotIdError::InvalidFormat(
                    "Failed to create a Snapshot ID. Input could not be parsed into a Snapshot ID."
                        .to_string(),
                )
            })?;

        let mut slice = [0u8; 8];
        slice.copy_from_slice(&bytes[..Self::LOCAL_ID_LENGTH_IN_BYTES]);
        let local_id = u64::from_be_bytes(slice);

        Ok(SnapshotId::from((canister_id, local_id)))
    }
}

impl std::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let local_id = self.get_local_snapshot_id();
        let canister_id = self.get_canister_id();
        write!(f, "{}-{}", canister_id, local_id)
    }
}

impl From<SnapshotId> for pbSnapshot {
    fn from(id: SnapshotId) -> Self {
        Self {
            content: id.to_vec(),
        }
    }
}

impl TryFrom<pbSnapshot> for SnapshotId {
    type Error = ProxyDecodeError;

    fn try_from(pb_snapshot_id: pbSnapshot) -> Result<Self, Self::Error> {
        SnapshotId::try_from(&pb_snapshot_id.content)
            .map_err(|_| ProxyDecodeError::Other("Invalid snapshot ID".to_string()))
    }
}

#[cfg(test)]
mod tests {
    pub use crate::{CanisterId, SnapshotId};

    #[test]
    fn test_snapshot_id_creation() {
        let canister_id = CanisterId::from_u64(243425);
        let local_id: u64 = 4;

        let mut expect_snapshot_id = [0u8; SnapshotId::MAX_LENGTH_IN_BYTES];
        let len = canister_id.get().as_slice().len();
        expect_snapshot_id[..8].copy_from_slice(&local_id.to_be_bytes());
        expect_snapshot_id[8..8 + len].copy_from_slice(canister_id.get().as_slice());

        let snapshot_id = SnapshotId::from((canister_id, local_id));
        assert_eq!(snapshot_id.get_canister_id(), canister_id);
        assert_eq!(
            snapshot_id.get_canister_id().get().as_slice(),
            canister_id.get().as_slice()
        );
        assert_eq!(snapshot_id.get_local_snapshot_id(), local_id);
    }
}
