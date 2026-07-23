use super::{PrincipalId, PrincipalIdClass, PrincipalIdError, SubnetId};
use candid::types::principal::PrincipalError;
use candid::{CandidType, Principal};
use ic_heap_bytes::DeterministicHeapBytes;
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use serde::{Deserialize, Serialize, de::Error};
use std::convert::TryFrom;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A type representing a canister's [`PrincipalId`].
///
/// We use a `bool` plus principal ID instead of an enum because some clients
/// require access to the underlying byte slice (which wouldn't be available in
/// the `u64` variant).
#[derive(Copy, Clone, Eq, DeterministicHeapBytes, Debug)]
pub struct CanisterId {
    /// Whether `id` is a `u64`-based canister ID (see [`CanisterId::from_u64`]),
    /// which allows `eq`/`cmp` to take a fast path over the leading `u64`.
    is_u64: bool,
    id: PrincipalId,
}

impl PartialEq for CanisterId {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        match (self.is_u64, other.is_u64) {
            (true, true) => as_u64(self.id) == as_u64(other.id),
            (true, false) | (false, true) => false,
            (false, false) => self.id == other.id,
        }
    }
}

impl Ord for CanisterId {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.is_u64 && other.is_u64 {
            as_u64(self.id).cmp(&as_u64(other.id))
        } else {
            self.id.cmp(&other.id)
        }
    }
}

impl PartialOrd for CanisterId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for CanisterId {
    #[inline]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        if self.is_u64 {
            // Fast path: a `u64`-based canister ID is fully determined by its
            // leading `u64`, so hashing just those 8 bytes is both sufficient
            // and consistent with `PartialEq` (which compares the same `u64`).
            as_u64(self.id).hash(hasher);
        } else {
            self.id.hash(hasher);
        }
    }
}

impl Serialize for CanisterId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.id.serialize(serializer)
    }
}

impl CandidType for CanisterId {
    fn id() -> candid::types::TypeId {
        candid::types::TypeId::of::<CanisterId>()
    }

    fn _ty() -> candid::types::Type {
        PrincipalId::_ty()
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        self.id.idl_serialize(serializer)
    }
}

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
            Self::InvalidPrincipalId(string) => write!(f, "Got an invalid principal id {string}"),
            Self::PrincipalIdParseError(err) => write!(f, "Could not parse principal: {err}"),
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
    /// Returns the ID of the management canister.
    pub const fn ic_00() -> Self {
        Self {
            is_u64: false,
            id: PrincipalId::new(0, [0; PrincipalId::MAX_LENGTH_IN_BYTES]),
        }
    }

    pub fn get_ref(&self) -> &PrincipalId {
        &self.id
    }

    pub fn get(self) -> PrincipalId {
        self.id
    }

    /// Converts WITHOUT any validation.
    ///
    /// If you want validation, use try_from_principal_id. Do NOT use
    /// CanisterId::try_from, because it lies: it does not actually return Err
    /// when the input is invalid.
    pub const fn unchecked_from_principal(principal_id: PrincipalId) -> Self {
        Self {
            is_u64: is_canister_id(principal_id),
            id: principal_id,
        }
    }

    // Keep this consistent with try_from_principal_id.
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

        Self {
            is_u64: true,
            id: PrincipalId::new_opaque_from_array(data, blob_length),
        }
    }

    // Keep this consistent with try_from_principal_id.
    pub const fn as_u64(&self) -> Option<u64> {
        if self.is_u64 {
            Some(as_u64(self.id))
        } else {
            None
        }
    }

    /// Converts from PrincipalId.
    ///
    /// The problem with CanisterId::try_from(principal_id) is that it lies.
    //
    // Keep this consistent with from_u64.
    pub fn try_from_principal_id(principal_id: PrincipalId) -> Result<Self, CanisterIdError> {
        if !is_canister_id(principal_id) {
            return Err(CanisterIdError::InvalidPrincipalId(format!(
                "Principal ID {} ({:?}) is not a valid canister ID: {} bytes, class {:?}",
                principal_id,
                principal_id.as_slice(),
                principal_id.len(),
                principal_id.class()
            )));
        }

        Ok(Self {
            is_u64: true,
            id: principal_id,
        })
    }
}

/// Returns true if the given `PrincipalId` is a valid canister ID (length 10,
/// byte 8 is 0x01, byte 9 is `Opaque`), false otherwise.
const fn is_canister_id(principal_id: PrincipalId) -> bool {
    const LENGTH: usize = std::mem::size_of::<u64>();
    let raw = principal_id.0.as_fixed_bytes();

    // The +2 accounts for the two sentinel bytes that are appended.
    if principal_id.0.len() != LENGTH as u8 + 2 {
        return false;
    }

    // Byte 9 (last; principal class) must be Opaque.
    if raw[LENGTH + 1] != PrincipalIdClass::Opaque as u8 {
        return false;
    }

    // Byte 8 (penultimate) must be 0x01.
    raw[LENGTH] == 0x01
}

/// Returns the `u64` value of a canister ID, assuming that the given
/// `PrincipalId` is a valid canister ID (see `is_canister_id`).
#[inline(always)]
const fn as_u64(principal_id: PrincipalId) -> u64 {
    let raw_bytes = principal_id.0.as_fixed_bytes();
    // SAFETY: `raw_bytes` is a `[u8; PrincipalId::MAX_LENGTH_IN_BYTES]` (29 bytes),
    // which is at least as large as a `u64` (8 bytes), so `transmute_copy` reads
    // only in-bounds source bytes (it copies `size_of::<u64>()` bytes from the
    // start). `u8` has alignment 1, so there is no alignment requirement on the
    // source, and every bit pattern is a valid `u64`.
    let raw_be = unsafe { std::mem::transmute_copy::<[u8; _], u64>(raw_bytes) };
    u64::from_be(raw_be)
}

impl AsRef<PrincipalId> for CanisterId {
    fn as_ref(&self) -> &PrincipalId {
        &self.id
    }
}

impl AsRef<[u8]> for CanisterId {
    fn as_ref(&self) -> &[u8] {
        self.id.as_slice()
    }
}

impl fmt::Display for CanisterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// Warning: This LIES: it does not return Err when the input is invalid. In
/// fact, this ALWAYS returns Ok.
///
/// We cannot simply "fix" this, because there are callers who rely on the
/// "always Ok (even when invalid)" behavior. (E.g. they might immediately call
/// unwrap, and assume that it never panics.)
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
        canister_id.id
    }
}

impl From<CanisterId> for pb::CanisterId {
    fn from(id: CanisterId) -> Self {
        Self {
            principal_id: Some(pb::PrincipalId::from(id.id)),
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
        Ok(CanisterId {
            is_u64: is_canister_id(principal_id),
            id: principal_id,
        })
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
        CanisterId::try_from(PrincipalId::deserialize(deserializer)?).map_err(D::Error::custom)
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
