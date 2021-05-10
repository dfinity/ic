//! The certified stream store public interface.
use ic_types::{
    xnet::{CertifiedStreamSlice, StreamIndex, StreamSlice},
    RegistryVersion, SubnetId,
};
use std::fmt;

/// Describes errors that can happen when encoding a certified stream slice.
#[derive(Debug, PartialEq, Eq)]
pub enum EncodeStreamError {
    NoStreamForSubnet(SubnetId),
    InvalidSliceBegin {
        slice_begin: StreamIndex,
        stream_begin: StreamIndex,
        stream_end: StreamIndex,
    },
    InvalidSliceIndices {
        witness_begin: Option<StreamIndex>,
        msg_begin: Option<StreamIndex>,
    },
}

impl fmt::Display for EncodeStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoStreamForSubnet(subnet_id) => write!(f, "No stream for subnet {}", subnet_id),
            Self::InvalidSliceBegin {
                slice_begin,
                stream_begin,
                stream_end,
            } => write!(
                f,
                "Requested slice begin {} is outside of stream message bounds [{}, {})",
                slice_begin, stream_begin, stream_end
            ),
            Self::InvalidSliceIndices {
                witness_begin,
                msg_begin,
            } => write!(
                f,
                "Invalid requested slice indices: witness_begin: {:?}, msg_begin: {:?}",
                witness_begin, msg_begin
            ),
        }
    }
}

impl std::error::Error for EncodeStreamError {}

/// Describes errors that can happen when decoding a certified stream slice.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeStreamError {
    InvalidSignature(SubnetId),
    InvalidDestination {
        sender: SubnetId,
        receiver: SubnetId,
    },
    SerializationError(String),
}

impl fmt::Display for DecodeStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature(subnet_id) => write!(
                f,
                "cannot validate signature of stream from subnet {}",
                subnet_id
            ),
            Self::InvalidDestination { sender, receiver } => write!(
                f,
                "stream from subnet {} is addressed at {}. Expected own subnet as destination.",
                sender, receiver
            ),
            Self::SerializationError(msg) => write!(f, "failed to deserialize content: {}", msg),
        }
    }
}
impl std::error::Error for DecodeStreamError {}

/// Responsible for fetching slices of certified streams and attaching
/// certifications to them.
///
/// Such certifications allow subnets to verify that a slice fetched from an
/// arbitrary node of a remote subnet is indeed genuine and agreed upon by a
/// majority of the replicas constituting that subnet.
pub trait CertifiedStreamStore: Send + Sync {
    /// Produces a certified slice of the stream for `remote_subnet` from the
    /// latest certified state, with a witness beginning at `witness_begin`;
    /// and messages beginning at `msg_begin` and containing at most `msg_limit`
    /// messages totaling at most `byte_limit` bytes.
    ///
    /// Precondition: `witness_begin.is_none() && msg_begin.is_none() ||
    /// witness_begin.unwrap() <= msg_begin.unwrap()`.
    fn encode_certified_stream_slice(
        &self,
        remote_subnet: SubnetId,
        witness_begin: Option<StreamIndex>,
        msg_begin: Option<StreamIndex>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> Result<CertifiedStreamSlice, EncodeStreamError>;

    /// Decode the certified stream slice of the stream coming from the
    /// `remote_subnet` and validate the signature on it with respect to the
    /// given `registry_version`.
    fn decode_certified_stream_slice(
        &self,
        remote_subnet: SubnetId,
        registry_version: RegistryVersion,
        certified_slice: &CertifiedStreamSlice,
    ) -> Result<StreamSlice, DecodeStreamError>;

    /// Decodes the certified stream slice without performing any validation.
    /// This method should only be used for decoding streams that have
    /// already been validated (e.g., payloads from previous blocks).
    fn decode_valid_certified_stream_slice(
        &self,
        certified_slice: &CertifiedStreamSlice,
    ) -> Result<StreamSlice, DecodeStreamError>;

    /// Returns the list of subnet ids for which we have outgoing certified
    /// streams.
    fn subnets_with_certified_streams(&self) -> Vec<SubnetId>;
}
