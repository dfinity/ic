//! A crate containing various basic types that are especially useful when
//! writing Rust canisters.

use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::types::v1 as pb;
use phantom_newtype::{AmountOf, DisplayerOf, Id};
use std::{convert::TryFrom, fmt};

mod canister_id;
mod pb_internal;
mod principal_id;

pub use candid::types::ic_types;
pub use canister_id::{CanisterId, CanisterIdError, CanisterIdError as CanisterIdBlobParseError};
pub use principal_id::{
    PrincipalId, PrincipalIdError, PrincipalIdError as PrincipalIdBlobParseError,
    PrincipalIdError as PrincipalIdParseError,
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
