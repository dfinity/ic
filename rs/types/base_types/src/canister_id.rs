use super::{PrincipalId, PrincipalIdClass, PrincipalIdError, SubnetId};
use candid::types::principal::PrincipalError;
use candid::{CandidType, Principal};
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use serde::de::Error;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};

/// A type representing a canister's [`PrincipalId`].
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Serialize)]
pub struct CanisterId(PrincipalId);

/// Represents an error that can occur when constructing a [`CanisterId`] from a
/// [`PrincipalId`].
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum CanisterIdError {
    /// An invalid [`PrincipalId`] was given.
    InvalidPrincipalId(String),
    /// The input string could not be parsed into a [`PrincipalId`].
    PrincipalIdParseError(PrincipalIdError),
}

impl fmt::Display for CanisterIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrincipalId(string) => write!(f, "Got an invalid principal id {}", string),
            Self::PrincipalIdParseError(err) => write!(f, "Could not parse principal: {}", err),
        }
    }
}

impl std::error::Error for CanisterIdError {}

impl From<PrincipalIdError> for CanisterIdError {
    fn from(v: PrincipalIdError) -> CanisterIdError {
        CanisterIdError::PrincipalIdParseError(v)
    }
}

impl From<PrincipalError> for CanisterIdError {
    fn from(v: PrincipalError) -> CanisterIdError {
        CanisterIdError::PrincipalIdParseError(PrincipalIdError(v))
    }
}

impl CanisterId {
    /// Returns the id of the management canister
    pub const fn ic_00() -> Self {
        Self(PrincipalId::new(0, [0; PrincipalId::MAX_LENGTH_IN_BYTES]))
    }

    pub fn get_ref(&self) -> &PrincipalId {
        &self.0
    }

    pub fn get(self) -> PrincipalId {
        self.0
    }

    /// No validation is performed on `principal_id` to check that it actually
    /// comes from a `CanisterId`.
    pub const fn unchecked_from_principal(principal_id: PrincipalId) -> Self {
        Self(principal_id)
    }

    pub const fn from_u64(val: u64) -> Self {
        // It is important to use big endian here to ensure that the generated
        // `PrincipalId`s still maintain ordering.
        let mut data = [0_u8; PrincipalId::MAX_LENGTH_IN_BYTES];

        // Specify explicitly the length, so as to assert at compile time that a u64
        // takes exactly 8 bytes
        let val: [u8; 8] = val.to_be_bytes();

        // for-loops in const fn are not supported
        data[0] = val[0];
        data[1] = val[1];
        data[2] = val[2];
        data[3] = val[3];
        data[4] = val[4];
        data[5] = val[5];
        data[6] = val[6];
        data[7] = val[7];

        // Even though not defined in the interface spec, add another 0x1 to the array
        // to create a sub category that could be used in future.
        data[8] = 0x01;

        let blob_length : usize = 8 /* the u64 */ + 1 /* the last 0x01 */;

        Self(PrincipalId::new_opaque_from_array(data, blob_length))
    }

    /// Converts from PrincipalId.
    ///
    /// There is a impl TryFrom<PrincipalId> for CanisterId, but we can't make it
    /// do the behavior of this (yet), because there could be callers of TryFrom
    /// who are implicitly relying on Err never being returned.
    //
    // Maintainers: Keep this consistent with from_u64.
    pub fn try_from_principal_id(principal_id: PrincipalId) -> Result<Self, CanisterIdError> {
        // Must be opaque.
        if principal_id.class() != Ok(PrincipalIdClass::Opaque) {
            return Err(CanisterIdError::InvalidPrincipalId(
                format!(
                    "Principal ID {} is of class {:?} (not Opaque).",
                    principal_id, principal_id.class(),
                )
            ));
        }

        // Must be of length 10.
        let raw = principal_id.as_slice();
        if raw.len() != 10 {
            return Err(CanisterIdError::InvalidPrincipalId(
                format!(
                    "Principal ID {} consists of {} bytes (not 10).",
                    principal_id, raw.len(),
                )
            ));
        }

        // Byte 8 (penultimate) must be 0x01.
        if raw[8] != 0x01 {
            return Err(CanisterIdError::InvalidPrincipalId(
                format!(
                    "Byte 8 (9th) of Principal ID {} is not 0x01: {}",
                    principal_id, hex::encode(raw),
                )
            ));
        }

        Ok(CanisterId(principal_id))
    }
}

impl AsRef<PrincipalId> for CanisterId {
    fn as_ref(&self) -> &PrincipalId {
        &self.0
    }
}

impl AsRef<[u8]> for CanisterId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Display for CanisterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Deprecated. Use CanisterId::try_from_principal_id.
impl TryFrom<PrincipalId> for CanisterId {
    type Error = CanisterIdError;

    fn try_from(principal_id: PrincipalId) -> Result<Self, Self::Error> {
        Ok(Self::unchecked_from_principal(principal_id))
    }
}

impl TryFrom<&[u8]> for CanisterId {
    type Error = CanisterIdError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(
            PrincipalId::try_from(bytes).map_err(CanisterIdError::PrincipalIdParseError)?,
        )
    }
}

impl TryFrom<&Vec<u8>> for CanisterId {
    type Error = CanisterIdError;
    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<Vec<u8>> for CanisterId {
    type Error = CanisterIdError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

// TODO(EXC-241)
impl From<SubnetId> for CanisterId {
    fn from(subnet_id: SubnetId) -> Self {
        CanisterId::unchecked_from_principal(subnet_id.get())
    }
}

impl From<CanisterId> for PrincipalId {
    fn from(canister_id: CanisterId) -> Self {
        canister_id.0
    }
}

impl From<CanisterId> for pb::CanisterId {
    fn from(id: CanisterId) -> Self {
        Self {
            principal_id: Some(pb::PrincipalId::from(id.0)),
        }
    }
}

impl TryFrom<pb::CanisterId> for CanisterId {
    type Error = ProxyDecodeError;

    fn try_from(canister_id: pb::CanisterId) -> Result<Self, Self::Error> {
        let principal_id = PrincipalId::try_from(
            canister_id
                .principal_id
                .ok_or(ProxyDecodeError::MissingField("CanisterId::principal_id"))?,
        )
        .map_err(|err| ProxyDecodeError::InvalidPrincipalId(Box::new(err)))?;
        Ok(CanisterId(principal_id))
    }
}

impl From<u64> for CanisterId {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl<'de> Deserialize<'de> for CanisterId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        // Not all principals are valid inside a CanisterId.
        // Therefore, deserialization must explicitly
        // transform the PrincipalId into a CanisterId.
        // A derived implementation of Deserialize would open
        // the door to invariant violation.
        let res = CanisterId::try_from(PrincipalId::deserialize(deserializer)?);
        let id = res.map_err(D::Error::custom)?;
        Ok(id)
    }
}

impl std::str::FromStr for CanisterId {
    type Err = CanisterIdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let principal_id =
            PrincipalId::from_str(input).map_err(CanisterIdError::PrincipalIdParseError)?;
        Ok(CanisterId::unchecked_from_principal(principal_id))
    }
}

impl From<CanisterId> for Principal {
    fn from(val: CanisterId) -> Self {
        let principal_id: PrincipalId = val.into();
        principal_id.into()
    }
}

#[cfg(test)]
mod tests;
