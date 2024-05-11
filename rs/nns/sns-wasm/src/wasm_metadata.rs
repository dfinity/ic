use crate::pb::v1::{
    get_wasm_metadata_response, GetWasmMetadataRequest as GetWasmMetadataRequestPb,
    GetWasmMetadataResponse as GetWasmMetadataResponsePb, MetadataSection as MetadataSectionPb,
    SnsWasmError as SnsWasmErrorPb,
};

impl TryFrom<GetWasmMetadataRequestPb> for [u8; 32] {
    type Error = String;

    /// First, etract the hash from the request payload. Second, convert it to a u8-array of
    /// length 32 (the size of our sha256 hash). Return an error if the input's length is incorrect.
    fn try_from(src: GetWasmMetadataRequestPb) -> Result<Self, Self::Error> {
        let Some(hash) = src.hash else {
            return Err("GetWasmMetadataRequest.bytes must be specified.".to_string());
        };

        let Ok(hash) = Self::try_from(hash) else {
            return Err("GetWasmMetadataRequest.bytes must contain exactly 32 bytes.".to_string());
        };

        Ok(hash)
    }
}

/// The internal representation of `MetadataSectionPb`.
pub struct MetadataSection {
    pub visibility: String,
    pub name: String,
    pub contents: Vec<u8>,
}

impl From<MetadataSection> for MetadataSectionPb {
    fn from(src: MetadataSection) -> Self {
        Self {
            visibility: Some(src.visibility),
            name: Some(src.name),
            contents: Some(src.contents),
        }
    }
}

impl From<Result<Vec<MetadataSection>, String>> for GetWasmMetadataResponsePb {
    fn from(src: Result<Vec<MetadataSection>, String>) -> Self {
        use get_wasm_metadata_response::{Ok, Result};
        let result = match src {
            Err(message) => Result::Error(SnsWasmErrorPb { message }),
            Ok(sections) => Result::Ok(Ok {
                sections: sections.into_iter().map(MetadataSectionPb::from).collect(),
            }),
        };
        Self {
            result: Some(result),
        }
    }
}
