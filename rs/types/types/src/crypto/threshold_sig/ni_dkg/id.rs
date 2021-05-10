//! Types related to the non-interactive DKG ID.
use super::*;
use ic_protobuf::types::v1 as pb;

#[cfg(test)]
mod tests;

/// The ID for non-interactive DKG. Identifies a DKG epoch.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NiDkgId {
    /// This field refers to the height of the block denoting the start of the
    /// computation of this DKG instance (resulting into a transcript later).
    pub start_block_height: Height,
    /// The id of the subnet performing the DKG computation.
    pub dealer_subnet: SubnetId,
    /// Differentiator for the threshold level of DKGs.
    pub dkg_tag: NiDkgTag,
    /// Indicates which subnet will use the result of this DKG.
    pub target_subnet: NiDkgTargetSubnet,
}

impl NiDkgId {
    pub fn from_option_protobuf(
        option_dkg_id: Option<pb::NiDkgId>,
        error_location: &str,
    ) -> Result<Self, String> {
        option_dkg_id
            .ok_or(format!("{} missing dkg_id", error_location))
            .and_then(|dkg_id| {
                NiDkgId::try_from(dkg_id)
                    .map_err(|err| format!("Error loading dkg_id in {}: {:?}", error_location, err))
            })
    }
}

impl fmt::Display for NiDkgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<NiDkgId> for NiDkgIdProto {
    fn from(ni_dkg_id: NiDkgId) -> Self {
        NiDkgIdProto {
            start_block_height: ni_dkg_id.start_block_height.get(),
            dealer_subnet: ni_dkg_id.dealer_subnet.get().into_vec(),
            dkg_tag: ni_dkg_id.dkg_tag as i32,
            remote_target_id: match ni_dkg_id.target_subnet {
                NiDkgTargetSubnet::Remote(target_id) => Some(target_id.0.to_vec()),
                NiDkgTargetSubnet::Local => None,
            },
        }
    }
}

impl TryFrom<NiDkgIdProto> for NiDkgId {
    type Error = NiDkgIdFromProtoError;

    fn try_from(ni_dkg_id_proto: NiDkgIdProto) -> Result<Self, Self::Error> {
        Ok(NiDkgId {
            start_block_height: Height::from(ni_dkg_id_proto.start_block_height),
            dealer_subnet: SubnetId::from(
                PrincipalId::try_from(ni_dkg_id_proto.dealer_subnet.as_slice())
                    .map_err(NiDkgIdFromProtoError::InvalidPrincipalId)?,
            ),
            dkg_tag: NiDkgTag::try_from(ni_dkg_id_proto.dkg_tag)
                .map_err(|_| NiDkgIdFromProtoError::InvalidDkgTag)?,
            target_subnet: match ni_dkg_id_proto.remote_target_id {
                None => NiDkgTargetSubnet::Local,
                // Note that empty bytes (which are different from None) will lead to an error.
                Some(bytes) => NiDkgTargetSubnet::Remote(
                    ni_dkg_target_id(bytes.as_slice())
                        .map_err(NiDkgIdFromProtoError::InvalidRemoteTargetIdSize)?,
                ),
            },
        })
    }
}

/// Occurs if the target ID size is invalid.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidNiDkgTargetIdSizeError;

/// Creates a target ID for the given data.
///
/// # Errors
/// * InvalidNiDkgTargetIdSizeError: if the target ID size is invalid.
pub fn ni_dkg_target_id(data: &[u8]) -> Result<NiDkgTargetId, InvalidNiDkgTargetIdSizeError> {
    if data.len() != NiDkgTargetId::SIZE {
        return Err(InvalidNiDkgTargetIdSizeError);
    }

    let mut result = [0; NiDkgTargetId::SIZE];
    result.copy_from_slice(data);
    Ok(NiDkgTargetId::new(result))
}

/// Occurs if the `NiDkgId` cannot be obtained from the corresponding protobuf.
#[derive(Debug, PartialEq, Eq)]
pub enum NiDkgIdFromProtoError {
    InvalidPrincipalId(PrincipalIdBlobParseError),
    InvalidDkgTag,
    InvalidRemoteTargetIdSize(InvalidNiDkgTargetIdSizeError),
}

impl From<NiDkgIdFromProtoError> for ic_protobuf::proxy::ProxyDecodeError {
    fn from(error: NiDkgIdFromProtoError) -> Self {
        use NiDkgIdFromProtoError::*;
        match error {
            InvalidPrincipalId(err) => Self::InvalidPrincipalId(Box::new(err)),
            InvalidDkgTag => Self::Other("Invalid DKG tag.".to_string()),
            InvalidRemoteTargetIdSize(_) => {
                Self::Other("Invalid remote target Id size.".to_string())
            }
        }
    }
}
