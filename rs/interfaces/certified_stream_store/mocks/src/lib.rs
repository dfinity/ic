use ic_interfaces_certified_stream_store::{
    CertifiedStreamStore, DecodeStreamError, EncodeStreamError,
};
use ic_types::{
    RegistryVersion, SubnetId,
    xnet::{CertifiedStreamSlice, StreamIndex, StreamSlice},
};
use mockall::*;

mock! {
    pub CertifiedStreamStore {}

    impl CertifiedStreamStore for CertifiedStreamStore {
        fn encode_certified_stream_slice(
            &self,
            remote_subnet: SubnetId,
            witness_begin: Option<StreamIndex>,
            msg_begin: Option<StreamIndex>,
            msg_limit: Option<usize>,
            byte_limit: Option<usize>,
        ) -> Result<CertifiedStreamSlice, EncodeStreamError>;

        fn decode_certified_stream_slice(
            &self,
            remote_subnet: SubnetId,
            registry_version: RegistryVersion,
            certified_slice: &CertifiedStreamSlice,
        ) -> Result<StreamSlice, DecodeStreamError>;

        fn decode_valid_certified_stream_slice(
            &self,
            certified_slice: &CertifiedStreamSlice,
        ) -> Result<StreamSlice, DecodeStreamError>;

        fn subnets_with_certified_streams(&self) -> Vec<SubnetId>;
    }
}
